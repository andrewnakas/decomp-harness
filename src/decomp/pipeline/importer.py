"""`decomp import`: ingest what is already known, so nothing is rediscovered.

A project rarely starts empty. There is a lifted corpus, a names table mined
from metadata, a struct header with cited offsets, execution traces, and the
verdicts of previous work. Each of those cost real effort to produce; importing
them with provenance is what keeps the model from being asked to derive them
again.
"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..core.db import parse_addr
from ..core.hashing import sha256_file
from ..core.stages import now_iso, stage

if TYPE_CHECKING:
    from ..core.config import Project


@dataclass
class ImportResult:
    kind: str
    counts: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def brief(self) -> str:
        body = "\t".join(f"{k}={v}" for k, v in self.counts.items())
        lines = [f"import\t{self.kind}\t{body}"]
        lines.extend(f"  {n}" for n in self.notes[:5])
        return "\n".join(lines)


# ----------------------------------------------------------------- image
@stage("import.image", inputs=lambda p, **kw: [str(kw.get("path")), kw.get("base")])
def import_image(project: Project, ctx, path: Path | str, base: int | None = None,
                 name: str = "") -> ImportResult:
    """Register the target image: the bytes everything else refers to."""
    path = Path(path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"image not found: {path}")
    base = base if base is not None else _parse_int(project.get("target.base_addr", 0))
    sha = sha256_file(path)
    row = {
        "id": 1,
        "name": name or project.get("project.name", path.stem),
        "platform": project.get("target.platform", "generic"),
        "arch": project.get("target.arch", ""),
        "endian": project.get("target.endian", "big"),
        "ptr_size": project.get("target.ptr_size", 4),
        "base_addr": base,
        "image_path": str(path),
        "image_sha256": sha,
        "ghidra_lang": project.get("target.ghidra_lang", ""),
        "recomp_path": project.get("target.recomp_path", ""),
        "adapter": project.get("project.target_adapter", "rawimage"),
    }
    project.db.upsert("target", row, "id")
    ctx.record(sha256=sha, size=path.stat().st_size)
    return ImportResult(
        "image",
        {"bytes": path.stat().st_size},
        [f"{path.name} @ 0x{base:08X} sha={sha[:12]}"],
    )


# ---------------------------------------------------------------- lifted
@stage(
    "import.lifted",
    inputs=lambda p, **kw: [str(kw.get("path")), _dir_sig(kw.get("path"))],
)
def import_lifted(project: Project, ctx, path: Path | str,
                  pattern: str = "*_recomp.*.cpp") -> ImportResult:
    """Index the lifted corpus into function, xref and const_ref rows.

    This is the single richest import: it establishes the full function list,
    every resolved call, and the constants each function materializes.
    """
    from ..adapters.groundtruth.lifted_rexglue import RexGlueLifted

    gt = RexGlueLifted(path, pattern=pattern,
                       cache_path=project.state / "cache" / "lifted_index.json")
    index = gt.index()
    if not index:
        raise FileNotFoundError(f"no lifted sources matching {pattern} under {path}")
    names = gt.names()

    functions = 0
    with project.db.tx():
        for addr, loc in index.items():
            project.db.upsert(
                "function",
                {
                    "addr": addr,
                    "tu": Path(loc.path).name,
                    "tu_line": loc.line,
                    "lifted_lines": loc.lines,
                    "vmx128": 1 if loc.vec else 0,
                    "updated_at": now_iso(),
                },
                "addr",
            )
            functions += 1

        # Names learned from call sites are real evidence: the lifter resolved
        # them from the binary, so they outrank anything a model would guess.
        symbols = 0
        for addr, symbol in names.items():
            is_import = symbol.startswith("__imp__")
            is_helper = symbol.startswith("__") and not is_import
            if addr in index or is_import or is_helper:
                project.db.upsert(
                    "function",
                    {
                        "addr": addr,
                        "name": symbol if (is_import or is_helper) else None,
                        "is_import": 1 if is_import else 0,
                        "is_helper": 1 if is_helper else 0,
                    },
                    "addr",
                )
            if is_import or is_helper:
                project.db.execute(
                    "INSERT INTO symbol_evidence (addr, name, kind, source, confidence, "
                    "created_at) VALUES (?,?,?,?,?,?)",
                    (addr, symbol, "lifted", "bl-site", 0.95, now_iso()),
                )
                symbols += 1

    project.db.meta_set("truth.lifted_dir", str(Path(path).resolve()))
    project.db.meta_set("truth.lifted_pattern", pattern)
    ctx.record(functions=functions, names=len(names))
    return ImportResult(
        "lifted",
        {"functions": functions, "resolved_names": len(names), "symbols": symbols},
        [f"vector functions: {sum(1 for loc in index.values() if loc.vec)}"],
    )


@stage("import.xrefs", inputs=lambda p, **kw: [kw.get("scope"), _dir_sig(p.db.meta_get('truth.lifted_dir'))])
def import_xrefs(project: Project, ctx, scope: str = "corpus") -> ImportResult:
    """Record call edges and constants for functions in scope.

    Done separately from the index because it reads every body: cheap for a
    subsystem, slow for all 47k functions.
    """
    from ..adapters.groundtruth.lifted_rexglue import from_project

    gt = from_project(project)
    where = "WHERE in_corpus=1" if scope == "corpus" else ""
    addrs = [r["addr"] for r in project.db.query(f"SELECT addr FROM function {where}")]
    edges = consts = 0
    with project.db.tx():
        for addr in addrs:
            for callee in gt.callees(addr):
                project.db.upsert(
                    "xref",
                    {
                        "caller": addr,
                        # 0 means "no known target": an indirect call through a
                        # function pointer, or a branch we could not resolve.
                        "callee": callee.addr or 0,
                        "callee_name": callee.name or "",
                        "kind": callee.kind,
                        "site_line": callee.site_line or 0,
                    },
                    ("caller", "callee", "callee_name", "site_line"),
                )
                edges += 1
            for value in gt.constants(addr):
                project.db.upsert(
                    "const_ref", {"addr": addr, "value": value, "kind": "unknown"},
                    ("addr", "value"),
                )
                consts += 1
    ctx.record(functions=len(addrs), edges=edges)
    return ImportResult("xrefs", {"functions": len(addrs), "edges": edges, "constants": consts})


# ----------------------------------------------------------------- names
@stage("import.names", inputs=lambda p, **kw: [str(kw.get("path")), _file_sig(kw.get("path"))])
def import_names(project: Project, ctx, path: Path | str, kind: str = "ingest",
                 confidence: float = 0.8) -> ImportResult:
    """Import a names table (CSV `addr,name` or TOML `"0xADDR" = "name"`)."""
    path = Path(path)
    pairs = _read_names(path)
    applied = 0
    with project.db.tx():
        for addr, name in pairs:
            project.db.execute(
                "INSERT INTO symbol_evidence (addr, name, kind, source, confidence, "
                "created_at) VALUES (?,?,?,?,?,?)",
                (addr, name, kind, path.name, confidence, now_iso()),
            )
            project.db.upsert(
                "function", {"addr": addr, "name": name, "name_confidence": confidence}, "addr"
            )
            applied += 1
    ctx.record(names=applied)
    return ImportResult("names", {"names": applied}, [f"from {path.name}"])


def _read_names(path: Path) -> list[tuple[int, str]]:
    text = path.read_text(errors="replace")
    pairs: list[tuple[int, str]] = []
    if path.suffix.lower() == ".toml":
        for line in text.splitlines():
            m = re.match(r'\s*"?(?:0x)?([0-9A-Fa-f]{6,8})"?\s*=\s*"([^"]+)"', line)
            if m:
                pairs.append((int(m.group(1), 16), m.group(2)))
        return pairs
    for row in csv.reader(text.splitlines()):
        if len(row) < 2 or not row[0].strip():
            continue
        try:
            pairs.append((parse_addr(row[0]), row[1].strip()))
        except ValueError:
            continue
    return pairs


# --------------------------------------------------------------- structs
FIELD_RE = re.compile(
    r"^\s*(?P<type>[A-Za-z_][\w ]*?)\s+(?P<name>[A-Za-z_]\w*)\s*"
    r"(?:\[(?P<array>[^\]]+)\])?\s*;\s*(?:/\*\s*\+0x(?P<off>[0-9A-Fa-f]+)(?P<note>[^*]*)\*/)?"
)
STRUCT_OPEN_RE = re.compile(r"^\s*typedef\s+struct\s*\{")
STRUCT_CLOSE_RE = re.compile(r"^\s*\}\s*(?P<name>\w+)\s*;")
CITE_RE = re.compile(r"sub_([0-9A-Fa-f]{8})")

TYPE_SIZES = {
    "uint8_t": 1, "int8_t": 1, "char": 1, "bool": 1,
    "uint16_t": 2, "int16_t": 2, "short": 2,
    "uint32_t": 4, "int32_t": 4, "int": 4, "float": 4, "rw_ptr": 4,
    "uint64_t": 8, "int64_t": 8, "double": 8,
}


@stage("import.structs", inputs=lambda p, **kw: [str(kw.get("path")), _file_sig(kw.get("path"))])
def import_structs(project: Project, ctx, path: Path | str) -> ImportResult:
    """Parse a recovered-layout header into struct/field rows with citations.

    The header's own convention is the evidence model: every field carries
    `+0xNN` and the comment above each struct names the functions the offsets
    were read from. Importing that keeps the citation attached to the fact.
    """
    path = Path(path)
    structs, fields, evidence = 0, 0, 0
    lines = path.read_text(errors="replace").splitlines()

    in_struct = False
    body: list[tuple[int, str]] = []
    preamble: list[str] = []

    with project.db.tx():
        for n, line in enumerate(lines):
            if STRUCT_OPEN_RE.match(line):
                in_struct, body = True, []
                continue
            if in_struct:
                close = STRUCT_CLOSE_RE.match(line)
                if close:
                    name = close.group("name")
                    cites = CITE_RE.findall("\n".join(preamble[-14:]))
                    added_f, added_e = _store_struct(
                        project, name, body, cites, path.name
                    )
                    structs += 1
                    fields += added_f
                    evidence += added_e
                    in_struct, preamble = False, []
                    continue
                body.append((n, line))
                continue
            preamble.append(line)

    ctx.record(structs=structs, fields=fields)
    return ImportResult(
        "structs",
        {"structs": structs, "fields": fields, "evidence": evidence},
        [f"from {path.name}"],
    )


def _store_struct(project: Project, name: str, body: list[tuple[int, str]],
                  cites: list[str], source: str) -> tuple[int, int]:
    project.db.upsert("struct", {"name": name, "origin": "ingest"}, "name")
    struct_id = project.db.scalar("SELECT id FROM struct WHERE name=?", (name,))

    fields = evidence = 0
    cursor = 0        # running offset, so fields without an explicit +0x still land
    size = 0
    for line_no, line in body:
        m = FIELD_RE.match(line)
        if not m:
            continue
        ctype = m.group("type").strip()
        fname = m.group("name")
        array = m.group("array")
        width = TYPE_SIZES.get(ctype.split()[-1], 4)
        count = _parse_int(array) if array else 1
        width *= max(1, count)

        offset = int(m.group("off"), 16) if m.group("off") else cursor
        cursor = offset + width
        size = max(size, cursor)
        if fname.startswith("_pad") or fname.startswith("_unknown"):
            continue

        project.db.upsert(
            "struct_field",
            {
                "struct_id": struct_id, "offset": offset, "size": width,
                "ctype": ctype, "name": fname, "status": "established",
                "confidence": 0.9,
            },
            ("struct_id", "offset"),
        )
        fields += 1
        field_id = project.db.scalar(
            "SELECT id FROM struct_field WHERE struct_id=? AND offset=?",
            (struct_id, offset),
        )
        note = (m.group("note") or "").strip()
        for cite in cites or [""]:
            project.db.execute(
                "INSERT INTO field_evidence (field_id, function_addr, access, kind, "
                "locator, snippet, confidence, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (
                    field_id,
                    int(cite, 16) if cite else None,
                    None,
                    "doc",
                    f"{source}:{line_no + 1}",
                    note[:200],
                    0.9,
                    now_iso(),
                ),
            )
            evidence += 1

    project.db.upsert("struct", {"name": name, "size": size, "origin": "ingest"}, "name")
    return fields, evidence


# ---------------------------------------------------------------- traces
@stage("import.trace", inputs=lambda p, **kw: [str(kw.get("path")), kw.get("profile"),
                                               _file_sig(kw.get("path"))])
def import_trace(project: Project, ctx, path: Path | str,
                 profile: str = "play") -> ImportResult:
    """Import a guest execution trace.

    Thread attribution is the cheapest, sharpest signal the harness has: the
    audio work went from 1,694 candidate functions to the 216 that actually run
    on the audio thread using nothing else.
    """
    path = Path(path)
    counts: dict[int, int] = {}
    threads: dict[int, str] = {}
    first_seq: dict[int, int] = {}
    seq = 0

    with open(path, errors="replace") as fh:
        for line in fh:
            parsed = _parse_trace_line(line)
            if not parsed:
                continue
            addr, thread = parsed
            seq += 1
            counts[addr] = counts.get(addr, 0) + 1
            if addr not in first_seq:
                first_seq[addr] = seq
                if thread:
                    threads[addr] = thread

    column = {"boot": "calls_boot", "play": "calls_play", "map": "calls_map"}.get(
        profile, "calls_play"
    )
    with project.db.tx():
        for addr, count in counts.items():
            project.db.upsert(
                "trace_call",
                {
                    "profile": profile, "addr": addr, "thread": threads.get(addr),
                    "count": count, "first_seq": first_seq.get(addr),
                },
                ("profile", "addr"),
            )
            project.db.upsert("function", {"addr": addr, column: count}, "addr")
            if threads.get(addr):
                project.db.execute(
                    "UPDATE function SET thread_first=COALESCE(thread_first,?) WHERE addr=?",
                    (threads[addr], addr),
                )
        project.db.execute(
            "UPDATE function SET hot = MAX(COALESCE(calls_boot,0), COALESCE(calls_play,0), "
            "COALESCE(calls_map,0))"
        )

    by_thread: dict[str, int] = {}
    for t in threads.values():
        by_thread[t] = by_thread.get(t, 0) + 1
    top = sorted(by_thread.items(), key=lambda kv: -kv[1])[:4]
    ctx.record(functions=len(counts), calls=seq)
    return ImportResult(
        "trace",
        {"functions": len(counts), "calls": seq},
        [f"{profile}: " + " ".join(f"{t}={n}" for t, n in top)] if top else [],
    )


def _parse_trace_line(line: str) -> tuple[int, str] | None:
    """Accept the tracer's TSV (seq cycles thread function ...) or a bare addr list."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split("\t") if "\t" in line else line.split()
    addr = None
    thread = ""
    for part in parts:
        token = part.strip()
        if token.lower().startswith("sub_") or re.fullmatch(r"(?:0x)?[0-9A-Fa-f]{8}", token):
            try:
                candidate = parse_addr(token)
            except ValueError:
                continue
            if addr is None:
                addr = candidate
        elif not token.replace(".", "").isdigit() and not thread and len(parts) > 1:
            thread = token[:40]
    if addr is None:
        return None
    return addr, thread


# ---------------------------------------------------------- prior verdicts
@stage("import.queue", inputs=lambda p, **kw: [str(kw.get("path")), _file_sig(kw.get("path"))])
def import_queue(project: Project, ctx, path: Path | str) -> ImportResult:
    """Import a previous project's work queue: statuses, gates, call counts.

    Re-verifying what is already verified is the most expensive kind of waste,
    because it costs both tokens and a session.
    """
    data = json.loads(Path(path).read_text())
    records = data.get("functions", data) if isinstance(data, dict) else data
    if isinstance(records, dict):
        items = records.items()
    else:
        items = [(r.get("addr"), r) for r in records]

    imported = 0
    statuses: dict[str, int] = {}
    with project.db.tx():
        for key, rec in items:
            if not isinstance(rec, dict):
                continue
            try:
                addr = parse_addr(str(rec.get("addr") or key))
            except (ValueError, TypeError):
                continue
            calls = rec.get("calls") or {}
            status = rec.get("status")
            row = {
                "addr": addr,
                "status": status,
                "tier": rec.get("tier"),
                "gate": rec.get("gate"),
                "gate_reason": rec.get("gate1_reason") or rec.get("gate_reason"),
                "attempts": rec.get("attempts"),
                "note": (rec.get("note") or "")[:300] or None,
                "thread_dom": rec.get("thread"),
                "calls_boot": calls.get("boot"),
                "calls_play": calls.get("play"),
                "calls_map": calls.get("map"),
                "lifted_lines": rec.get("lines"),
                "last_divergence": rec.get("last_divergence"),
                "updated_at": now_iso(),
            }
            project.db.upsert("function", {k: v for k, v in row.items() if v is not None}, "addr")
            imported += 1
            if status:
                statuses[status] = statuses.get(status, 0) + 1

    ctx.record(imported=imported)
    top = sorted(statuses.items(), key=lambda kv: -kv[1])[:6]
    return ImportResult(
        "queue",
        {"functions": imported},
        [" ".join(f"{s}={n}" for s, n in top)] if top else [],
    )


# ----------------------------------------------------------------- notes
@stage("import.notes", inputs=lambda p, **kw: [str(kw.get("path")), _dir_sig(kw.get("path"))])
def import_notes(project: Project, ctx, path: Path | str) -> ImportResult:
    """Import per-function notes, trimmed to what fits in a packet header.

    The originals average 4 KB each; roughly 850 KB of prose across a corpus.
    Only the first substantive lines ever informed a decision, so that is what
    is kept, with the full text left where it is.
    """
    path = Path(path)
    files = sorted(path.glob("sub_*.md")) if path.is_dir() else []
    kept = 0
    with project.db.tx():
        for f in files:
            try:
                addr = parse_addr(f.stem)
            except ValueError:
                continue
            summary = _summarize_note(f.read_text(errors="replace"))
            if not summary:
                continue
            project.db.upsert("function", {"addr": addr, "note": summary}, "addr")
            kept += 1
    ctx.record(notes=kept)
    return ImportResult("notes", {"notes": kept, "files": len(files)})


def _summarize_note(text: str) -> str:
    """First real prose lines of a note, capped at the packet budget."""
    out: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("```"):
            break
        out.append(stripped)
        if sum(len(o) for o in out) > 260:
            break
    return " ".join(out)[:300]


# ------------------------------------------------------- decompiler output
@stage("import.decomp", inputs=lambda p, **kw: [str(kw.get("path")), _dir_sig(kw.get("path"))])
def import_decompiled(project: Project, ctx, path: Path | str,
                      pattern: str = "sub_*.c") -> ImportResult:
    """Register existing decompiler output as the C view for each function.

    The files stay where they are; the harness records where to find them and
    what they cost, so a packet can pick the cheaper body form without reading
    both.
    """
    from ..core.tokens import estimate
    from ..views.cnorm import has_unresolved_branch, is_usable, normalize, signature_of

    path = Path(path)
    files = sorted(path.glob(pattern)) if path.is_dir() else []
    if not files:
        raise FileNotFoundError(f"no files matching {pattern} under {path}")

    registered = failed = branchy = 0
    with project.db.tx():
        for f in files:
            try:
                addr = parse_addr(f.stem)
            except ValueError:
                continue
            source = f.read_text(errors="replace")
            usable = is_usable(source)
            if not usable:
                failed += 1
            if has_unresolved_branch(source):
                branchy += 1
            view = normalize(source)
            project.db.upsert(
                "view_cache",
                {
                    "addr": addr, "kind": "ghidra_c", "path": str(f),
                    "tokens": estimate(source), "lines": source.count("\n") + 1,
                    "version_hash": _file_sig(f),
                },
                ("addr", "kind"),
            )
            update = {
                "addr": addr,
                "ghidra_lines": view.text.count("\n") + 1,
                "decompile_ok": 1 if usable else 0,
            }
            sig = signature_of(source)
            if sig:
                update["signature"] = sig[:200]
            project.db.upsert("function", update, "addr")
            registered += 1

    ctx.record(registered=registered, failed=failed)
    return ImportResult(
        "decomp",
        {"functions": registered, "not_recovered": failed, "unnamed_branch": branchy},
        [f"{failed} need the authoritative assembly instead"] if failed else [],
    )


# ----------------------------------------------------------------- utils
def _parse_int(value: Any, default: int = 0) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return default
    return default


def _file_sig(path: Any) -> str:
    try:
        p = Path(path)
        st = p.stat()
        return f"{st.st_size}:{int(st.st_mtime)}"
    except (OSError, TypeError):
        return "missing"


def _dir_sig(path: Any) -> str:
    from ..core.hashing import dir_signature

    try:
        return dir_signature(Path(path))
    except (OSError, TypeError):
        return "missing"
