"""The packet: everything the model gets, and nothing else.

This is the file where token cost is decided. The rules it enforces:

  * No file paths and no instruction to read anything. The model has no file
    tools; the packet is the whole world. Repo discovery was the largest single
    sink in the manual sessions.
  * The authoritative body appears once, in the cheapest form that still answers
    the question. Decompiled C when the decompiler succeeded; collapsed assembly
    when it did not, or when lane order matters.
  * Facts the harness already knows are stated, not re-derived: resolved callee
    names, folded constants, recovered field names, the store census, and what
    a verified sibling was called.
  * Everything is budgeted. A packet that will not fit says what it dropped.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..core.db import addr_str
from ..core.tokens import estimate

if TYPE_CHECKING:
    from ..core.config import Project

# Body forms, cheapest first.
FORM_C = "c"
FORM_ASM = "asm"
FORM_BOTH = "both"


@dataclass
class PacketBudget:
    target_tokens: int = 1000
    max_tokens: int = 6000
    max_body_lines: int = 220
    max_siblings: int = 2
    max_callees: int = 10
    max_constants: int = 8


@dataclass
class Packet:
    addr: int
    text: str
    tokens: int
    form: str
    sections: dict[str, int] = field(default_factory=dict)
    dropped: list[str] = field(default_factory=list)

    def brief(self) -> str:
        parts = " ".join(f"{k}={v}" for k, v in self.sections.items())
        line = f"{addr_str(self.addr)}\t{self.tokens} tok\tform={self.form}\t{parts}"
        if self.dropped:
            line += "\tdropped: " + ", ".join(self.dropped)
        return line


_FIELD_CACHE: dict[tuple[int, str], dict[int, str]] = {}


def _fields_for(project: Project, struct_hint: str = "") -> dict[int, str]:
    """Offset -> 'Struct.field', but only where the answer is unambiguous.

    An offset several structs claim tells the reader nothing and costs tokens to
    say. Worse, picking one of them states a fact the harness has not
    established, and offsets aliasing across unrelated structures is exactly
    what sent three of the audio project's investigations down the wrong path.
    So an ambiguous offset gets no annotation unless a struct hint resolves it.
    """
    # Layouts change only when a struct is imported or proposed, so the map is
    # rebuilt on that count rather than on every packet.
    version = project.db.scalar("SELECT COUNT(*) FROM struct_field", (), 0)
    key = (version, struct_hint)
    cached = _FIELD_CACHE.get(key)
    if cached is not None:
        return cached

    by_offset: dict[int, list[str]] = {}
    for r in project.db.query(
        "SELECT s.name AS struct, f.offset, f.name FROM struct_field f "
        "JOIN struct s ON s.id=f.struct_id WHERE f.name IS NOT NULL"
    ):
        by_offset.setdefault(r["offset"], []).append((r["struct"], r["name"]))

    out: dict[int, str] = {}
    for off, candidates in by_offset.items():
        if struct_hint:
            matching = [c for c in candidates if c[0] == struct_hint]
            if len(matching) == 1:
                out[off] = f"{matching[0][0]}.{matching[0][1]}"
                continue
        if len(candidates) == 1:
            out[off] = f"{candidates[0][0]}.{candidates[0][1]}"
    _FIELD_CACHE.clear()
    _FIELD_CACHE[key] = out
    return out


def build(project: Project, addr: int, budget: PacketBudget | None = None,
          form: str = "", divergence: str = "", attempt: int = 1) -> Packet:
    """Assemble one function's packet."""
    from ..adapters.groundtruth.lifted_rexglue import from_project as truth_from_project
    from .cnorm import has_unresolved_branch, is_usable, normalize

    budget = budget or PacketBudget(
        target_tokens=project.get("budget.packet_tokens_target", 1000),
        max_tokens=project.get("budget.packet_tokens_max", 6000),
    )
    fn = project.db.one("SELECT * FROM function WHERE addr=?", (addr,))
    if not fn:
        raise KeyError(f"{addr_str(addr)} is not in this project")

    gt = truth_from_project(project)
    field_names = _fields_for(project)
    dropped: list[str] = []
    sections: dict[str, int] = {}

    # ---------------------------------------------------------------- header
    lines: list[str] = [_header(fn, attempt)]

    sig = _signature(project, fn, addr)
    if sig:
        lines.append(f"sig: {sig}")

    callees = _callee_line(project, addr, budget.max_callees)
    if callees:
        lines.append(f"callees: {callees}")

    consts = _constants_line(project, gt, addr, budget.max_constants)
    if consts:
        lines.append(f"constants: {consts}")

    stores = _store_census_line(project, addr)
    if stores:
        lines.append(f"stores: {stores}")

    windows = _window_hint(project, addr)
    if windows:
        lines.append(f"windows: {windows}")

    siblings = _sibling_line(project, fn, budget.max_siblings)
    if siblings:
        lines.append(f"verified siblings: {siblings}")

    if fn.get("note"):
        lines.append(f"note: {fn['note']}")

    sections["header"] = estimate("\n".join(lines))

    # ------------------------------------------------------------------ body
    c_source = _decompiled(project, addr)
    chosen = form or _choose_form(fn, c_source, is_usable)

    if chosen in (FORM_C, FORM_BOTH) and c_source:
        view = normalize(c_source, field_names)
        body = view.text
        if has_unresolved_branch(c_source):
            body += "\n// note: a branch target here is unnamed in the decompiler output"
        lines.append("--- decompiled C ---")
        lines.append(body)
        sections["c"] = estimate(body)

    if chosen in (FORM_ASM, FORM_BOTH):
        asm = gt.collapse(addr, max_lines=budget.max_body_lines)
        if asm:
            label = "--- assembly (authoritative) ---"
            if chosen == FORM_BOTH:
                label = "--- assembly ---"
            lines.append(label)
            lines.append(asm)
            sections["asm"] = estimate(asm)
            total_asm_lines = len(gt.collapse(addr).splitlines())
            if total_asm_lines > budget.max_body_lines:
                dropped.append(f"{total_asm_lines - budget.max_body_lines} asm lines")

    if divergence:
        lines.append("--- divergence from the previous attempt ---")
        lines.append(divergence)
        sections["divergence"] = estimate(divergence)

    text = "\n".join(lines)
    tokens = estimate(text)

    # A packet over budget loses its most expensive section rather than being
    # sent anyway: an oversized call is how a cheap function becomes expensive.
    if tokens > budget.max_tokens and sections.get("asm") and sections.get("c"):
        lines = [ln for ln in lines if not ln.startswith("  ")]
        text = "\n".join(lines)
        tokens = estimate(text)
        dropped.append("assembly (over budget)")
        sections.pop("asm", None)

    return Packet(addr=addr, text=text, tokens=tokens, form=chosen,
                  sections=sections, dropped=dropped)


# ------------------------------------------------------------------ pieces
def _header(fn: dict[str, Any], attempt: int) -> str:
    bits = [f"# {addr_str(fn['addr'])}"]
    if fn.get("name"):
        bits.append(fn["name"])
    bits.append(f"tier={fn.get('tier') or '?'}")
    calls = {
        k: fn.get(f"calls_{k}") for k in ("boot", "play", "map")
        if fn.get(f"calls_{k}")
    }
    if calls:
        bits.append("calls=" + ",".join(f"{k}:{v}" for k, v in calls.items()))
    if fn.get("thread_first"):
        bits.append(f"thread={fn['thread_first']}")
    bits.append(f"gate={fn.get('gate') or 'pass'}")
    if fn.get("vmx128"):
        bits.append("vector")
    bits.append(f"lines={fn.get('lifted_lines') or '?'}")
    bits.append(f"attempt={attempt}")
    return "  ".join(bits)


def _signature(project: Project, fn: dict[str, Any], addr: int) -> str:
    if fn.get("signature"):
        return fn["signature"]
    source = _decompiled(project, addr)
    if source:
        from .cnorm import signature_of

        sig = signature_of(source)
        if sig:
            return sig
    return ""


FRAME_HELPERS = ("__savegprlr", "__restgprlr", "__savefpr", "__restfpr",
                 "__savevmx", "__restvmx")


def _is_frame_helper(name: str | None) -> bool:
    return bool(name) and name.startswith(FRAME_HELPERS)


def _callee_line(project: Project, addr: int, limit: int) -> str:
    rows = project.db.query(
        "SELECT callee, callee_name, kind FROM xref WHERE caller=? "
        "ORDER BY kind, site_line LIMIT ?",
        (addr, limit + 4),
    )
    if not rows:
        return ""
    parts: list[str] = []
    indirect = 0
    for r in rows:
        if r["kind"] == "indirect":
            indirect += 1
            continue
        if r["kind"] == "helper" or _is_frame_helper(r["callee_name"]):
            # Register save/restore stubs are frame bookkeeping. A port never
            # reproduces the prologue, so naming them costs tokens and teaches
            # nothing. The assembly view drops them for the same reason.
            continue
        status = project.db.scalar(
            "SELECT status FROM function WHERE addr=?", (r["callee"],)
        )
        mark = ""
        if status in ("verified", "promoted"):
            mark = " [ported]"
        elif status in ("gate1", "gate2", "gate3"):
            mark = f" [{status}]"
        parts.append(f"{r['callee_name']}{mark}")
        if len(parts) >= limit:
            break
    if indirect:
        parts.append(f"{indirect} indirect")
    return " | ".join(parts)


def _constants_line(project: Project, gt, addr: int, limit: int) -> str:
    rows = project.db.query(
        "SELECT value, string_preview FROM const_ref WHERE addr=? ORDER BY value LIMIT ?",
        (addr, limit),
    )
    values = [r["value"] for r in rows]
    if not values:
        values = gt.constants(addr)[:limit]
    if not values:
        return ""
    out = []
    for v in values:
        name = project.db.scalar("SELECT name FROM function WHERE addr=?", (v,))
        out.append(f"0x{v:08X}" + (f" ({name})" if name else ""))
    return " ".join(out)


def _store_census_line(project: Project, addr: int) -> str:
    row = project.db.one("SELECT store_prov_json FROM gate WHERE addr=?", (addr,))
    if not row or not row.get("store_prov_json"):
        return ""
    import json

    try:
        stores = json.loads(row["store_prov_json"])
    except (json.JSONDecodeError, TypeError):
        return ""
    if not stores:
        return "none"
    by_base: dict[str, int] = {}
    for s in stores:
        by_base[s.get("base", "?")] = by_base.get(s.get("base", "?"), 0) + 1
    return f"{len(stores)} (" + ", ".join(f"{k}:{v}" for k, v in sorted(by_base.items())) + ")"


def _window_hint(project: Project, addr: int) -> str:
    row = project.db.one("SELECT windows_json FROM gate WHERE addr=?", (addr,))
    if not row or not row.get("windows_json"):
        return ""
    import json

    try:
        windows = json.loads(row["windows_json"])
    except (json.JSONDecodeError, TypeError):
        return ""
    if not windows:
        return ""
    # A function's own frame is never windowed and never compared, so stack
    # stores are noise here.
    windows = [w for w in windows if (w.get("base") or "") not in ("r1", "sp")]
    if not windows:
        return "none outside the frame"
    parts = []
    any_deref = False
    for w in windows[:8]:
        base = w.get("base") or "r3"
        off = w.get("offset")
        chain = w.get("deref") or []
        if chain:
            any_deref = True
            # Spell the derivation out. An implicit "this base needs a read"
            # invites a window rooted at the entry register instead of at the
            # pointer it holds, which rewinds the wrong memory entirely.
            addr = f"[{base}+{chain[0]}]"
            for step in chain[1:]:
                addr = f"[{addr}+{step}]"
        else:
            addr = base
        suffix = f"+{off}" if off else ""
        parts.append(f"{addr}{suffix}:{w.get('len')}")
    tail = f" (+{len(windows) - 8} more)" if len(windows) > 8 else ""
    hint = ("    ([r3+4] means: load a pointer from r3+4, then offset from there)"
            if any_deref else "")
    return " ".join(parts) + tail + hint


def _sibling_line(project: Project, fn: dict[str, Any], limit: int) -> str:
    if not fn.get("family_id"):
        return ""
    rows = project.db.query(
        "SELECT addr, name FROM function WHERE family_id=? AND addr!=? "
        "AND status IN ('verified','promoted') ORDER BY COALESCE(hot,0) DESC LIMIT ?",
        (fn["family_id"], fn["addr"], limit),
    )
    return " ".join(
        f"{addr_str(r['addr'])}" + (f" ({r['name']})" if r["name"] else "") for r in rows
    )


def _decompiled(project: Project, addr: int) -> str:
    from pathlib import Path

    row = project.db.one(
        "SELECT path FROM view_cache WHERE addr=? AND kind='ghidra_c'", (addr,)
    )
    if row and row.get("path"):
        p = Path(row["path"])
        if p.is_file():
            return p.read_text(errors="replace")
    return ""


def _choose_form(fn: dict[str, Any], c_source: str, usable) -> str:
    """Which body form answers the question most cheaply.

    Assembly wins for vector work regardless of what the decompiler produced:
    lane order is the thing being ported, and scalar C hides it behind temporaries.
    """
    if fn.get("vmx128"):
        return FORM_ASM
    if not c_source or not usable(c_source):
        return FORM_ASM
    return FORM_C
