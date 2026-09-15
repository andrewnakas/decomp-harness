"""RexGlue lifted C++ as ground truth.

A static recompiler emits one C++ statement per guest instruction with the
original mnemonic in a comment above it:

    // bl 0x82f52114
    ctx.lr = 0x82AF0340;
    __savegprlr_27(ctx, base);
    // lis r10,-32237
    ctx.r10.s64 = -2112684032;

That makes the generated tree a complete, machine-readable disassembly. This
adapter mines it for everything the harness would otherwise pay a model to
work out: function boundaries, resolved callee names, materialized constants,
and the properties that decide whether a function can be verified at all.

Absorbs the logic of the audio project's extract_lifted.py and
resolve_callees.py into one streaming pass over the corpus.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from .base import Callee, GroundTruth, TruthFlags, TruthLoc

if TYPE_CHECKING:
    from ...core.config import Project

# --- patterns ---------------------------------------------------------------
RE_DEFINE = re.compile(r"DEFINE_REX_FUNC\(sub_([0-9A-Fa-f]{8})\)")
RE_BL = re.compile(r"//\s*b(?:l|la)\s+0x([0-9a-fA-F]{8})\s*$")
RE_CALL = re.compile(r"^\s*(__imp__\w+|__\w+|sub_[0-9A-Fa-f]{8})\s*\(")
RE_MNEMONIC = re.compile(r"^\s*//\s*([a-z][a-z0-9_.]*)(?:\s+(.*))?$")
RE_LABEL = re.compile(r"^\s*(loc_[0-9A-Fa-f]{8}):")

# Runtime constructs that make a call unreplayable on rewound memory.
RE_INDIRECT = re.compile(r"REX_CALL_INDIRECT|REX_INDIRECT_CALL|\(\*\s*\w*[Ff]unc")
RE_TIMEBASE = re.compile(r"REX_QUERY_TIMEBASE|__builtin_ppc_mftb|\bmftb\b")
RE_LOCK = re.compile(r"REX_ENTER_GLOBAL_LOCK|REX_LEAVE_GLOBAL_LOCK")
RE_STORE = re.compile(r"\bREX_(?:MM_)?STORE_(?:U|F|V)?\w*\(")
RE_LOAD = re.compile(r"\bREX_(?:MM_)?LOAD_(?:U|F|V)?\w*\(")

# Xenon's extended vector ISA, which Ghidra's PowerPC models do not decode.
VMX_HINT = re.compile(r"128\b|^v[a-z]|^lvx|^stvx|^lvl|^lvr|^stvl|^stvr")
FLOAT_HINT = re.compile(r"^(f[a-z]|lfs|lfd|stfs|stfd)")

INDEX_META_KEY = "truth.rexglue.index"
SIG_META_KEY = "truth.rexglue.signature"


def _sign16(value: int) -> int:
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


class RexGlueLifted(GroundTruth):
    id = "lifted_rexglue"

    def __init__(self, generated_dir: Path | str, pattern: str = "*_recomp.*.cpp",
                 cache_path: Path | None = None):
        self.dir = Path(generated_dir)
        self.pattern = pattern
        self.cache_path = cache_path
        self._index: dict[int, TruthLoc] | None = None
        self._names: dict[int, str] | None = None
        self._body_cache: dict[int, str] = {}

    # ------------------------------------------------------------ discovery
    def sources(self) -> list[Path]:
        if not self.dir.is_dir():
            return []
        return sorted(self.dir.glob(self.pattern))

    def signature(self) -> str:
        """Cheap fingerprint of the corpus, so the index is rebuilt only when it changes."""
        from ...core.hashing import sha256_text

        parts = [f"{p.name}:{p.stat().st_size}:{int(p.stat().st_mtime)}" for p in self.sources()]
        return sha256_text("\n".join(parts))

    # ---------------------------------------------------------------- index
    def build_index(self) -> tuple[dict[int, TruthLoc], dict[int, str]]:
        """One streaming pass: function boundaries and the `bl` name map.

        Both were separate scripts and separate passes over 289 MB before; a
        single pass makes re-indexing cheap enough to do on demand.
        """
        index: dict[int, TruthLoc] = {}
        names: dict[int, str] = {}

        for path in self.sources():
            current_addr: int | None = None
            current_line = 0
            depth = 0
            started = False
            vec = 0
            pending_bl: int | None = None
            lookahead = 0

            with open(path, errors="ignore") as fh:
                for n, line in enumerate(fh):
                    # --- resolve `// bl 0xADDR` to the symbol it lowered to.
                    # The lifter emits the comment, then `ctx.lr = ...`, then the
                    # call, so the call is not always on the next line.
                    if pending_bl is not None:
                        m = RE_CALL.match(line)
                        if m:
                            names.setdefault(pending_bl, m.group(1))
                            pending_bl = None
                        else:
                            lookahead -= 1
                            if lookahead <= 0:
                                pending_bl = None
                    else:
                        m = RE_BL.search(line)
                        if m:
                            pending_bl, lookahead = int(m.group(1), 16), 3

                    # --- function boundaries
                    m = RE_DEFINE.search(line)
                    if m:
                        if current_addr is not None:
                            index[current_addr] = TruthLoc(
                                current_addr, str(path), current_line,
                                n - current_line, vec,
                            )
                        current_addr = int(m.group(1), 16)
                        current_line = n
                        depth = 0
                        started = False
                        vec = 0

                    if current_addr is None:
                        continue

                    mm = RE_MNEMONIC.match(line)
                    if mm and VMX_HINT.search(mm.group(1)):
                        vec += 1

                    opens = line.count("{")
                    depth += opens - line.count("}")
                    if opens:
                        started = True
                    if started and depth <= 0:
                        index[current_addr] = TruthLoc(
                            current_addr, str(path), current_line,
                            n - current_line + 1, vec,
                        )
                        current_addr = None

            if current_addr is not None:  # file ended mid-function
                index[current_addr] = TruthLoc(current_addr, str(path), current_line, 0, vec)

        return index, names

    def index(self) -> Mapping[int, TruthLoc]:
        if self._index is None:
            self._load_or_build()
        return self._index or {}

    def names(self) -> Mapping[int, str]:
        if self._names is None:
            self._load_or_build()
        return self._names or {}

    def _load_or_build(self) -> None:
        sig = self.signature()
        if self.cache_path and self.cache_path.is_file():
            try:
                blob = json.loads(self.cache_path.read_text())
                if blob.get("signature") == sig:
                    self._index = {
                        int(k): TruthLoc(int(k), v[0], v[1], v[2], v[3])
                        for k, v in blob["index"].items()
                    }
                    self._names = {int(k): v for k, v in blob["names"].items()}
                    return
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                pass
        self._index, self._names = self.build_index()
        if self.cache_path:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps({
                "signature": sig,
                "index": {
                    str(a): [loc.path, loc.line, loc.lines, loc.vec]
                    for a, loc in self._index.items()
                },
                "names": {str(a): n for a, n in self._names.items()},
            }))

    # ----------------------------------------------------------------- body
    def body(self, addr: int) -> str:
        if addr in self._body_cache:
            return self._body_cache[addr]
        loc = self.index().get(addr)
        if loc is None:
            return ""
        out: list[str] = []
        depth, started = 0, False
        with open(loc.path, errors="ignore") as fh:
            for n, line in enumerate(fh):
                if n < loc.line:
                    continue
                out.append(line)
                opens = line.count("{")
                depth += opens - line.count("}")
                if opens:
                    started = True
                if started and depth <= 0:
                    break
        text = "".join(out)
        if len(self._body_cache) < 256:
            self._body_cache[addr] = text
        return text

    def location(self, addr: int) -> TruthLoc | None:
        return self.index().get(addr)

    # -------------------------------------------------------------- callees
    def callees(self, addr: int) -> list[Callee]:
        """Resolved callees for one function, from its own `bl` sites."""
        body = self.body(addr)
        if not body:
            return []
        names = self.names()
        out: list[Callee] = []
        seen: set[tuple[int | None, str]] = set()
        pending: int | None = None
        lookahead = 0
        pending_line = 0

        for n, line in enumerate(body.splitlines()):
            if pending is not None:
                m = RE_CALL.match(line)
                if m:
                    out.append(_make_callee(pending, m.group(1), pending_line))
                    pending = None
                    continue
                lookahead -= 1
                if lookahead <= 0:
                    target = pending
                    out.append(_make_callee(target, names.get(target, ""), pending_line))
                    pending = None
                continue
            m = RE_BL.search(line)
            if m:
                pending, lookahead, pending_line = int(m.group(1), 16), 3, n
                continue
            if RE_INDIRECT.search(line):
                out.append(Callee(None, "(indirect)", "indirect", n))

        deduped = []
        for c in out:
            key = (c.addr, c.name)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(c)
        return deduped

    # ------------------------------------------------------------ constants
    def constants(self, addr: int) -> list[int]:
        """Addresses materialized by lis/addi/ori pairs, folded arithmetically.

        Reading these by eye once produced this project's first shadow
        divergence: a misread digit in `lfs f13,18868(r9)`. The arithmetic is
        three lines of code, so the harness always does it.
        """
        body = self.body(addr)
        if not body:
            return []
        regs: dict[str, int] = {}
        found: list[int] = []

        for line in body.splitlines():
            m = RE_MNEMONIC.match(line)
            if not m:
                continue
            mnem, args = m.group(1), (m.group(2) or "").strip()
            parts = [p.strip() for p in args.split(",")]

            if mnem in ("lis", "lil") and len(parts) == 2:
                try:
                    regs[parts[0]] = (int(parts[1], 0) & 0xFFFF) << 16
                except ValueError:
                    continue
            elif mnem in ("addi", "addic", "subi") and len(parts) == 3:
                src = regs.get(parts[1])
                if src is None:
                    regs.pop(parts[0], None)
                    continue
                try:
                    imm = _sign16(int(parts[2], 0))
                except ValueError:
                    continue
                if mnem == "subi":
                    imm = -imm
                regs[parts[0]] = (src + imm) & 0xFFFFFFFF
                found.append(regs[parts[0]])
            elif mnem == "ori" and len(parts) == 3:
                src = regs.get(parts[1])
                if src is None:
                    continue
                try:
                    regs[parts[0]] = (src | (int(parts[2], 0) & 0xFFFF)) & 0xFFFFFFFF
                except ValueError:
                    continue
                found.append(regs[parts[0]])
            elif len(parts) == 2 and "(" in parts[1]:
                # A load or store through a register we have folded: the
                # effective address is a real constant reference.
                inner = parts[1]
                try:
                    off_text, reg = inner.split("(", 1)
                    reg = reg.rstrip(")")
                    base = regs.get(reg)
                    if base is not None:
                        found.append((base + _sign16(int(off_text or "0", 0))) & 0xFFFFFFFF)
                except (ValueError, IndexError):
                    continue
            elif mnem.startswith(("b", "cmp")) or mnem in ("mtctr", "mtlr"):
                continue
            elif parts and parts[0] in regs and mnem not in ("stw", "sth", "stb", "stfs", "stfd"):
                # The register was reassigned by something we do not model.
                regs.pop(parts[0], None)

        seen: set[int] = set()
        return [v for v in found if not (v in seen or seen.add(v))]

    # ---------------------------------------------------------------- flags
    def flags(self, addr: int) -> TruthFlags:
        body = self.body(addr)
        f = TruthFlags()
        if not body:
            return f
        for line in body.splitlines():
            if RE_INDIRECT.search(line):
                f.indirect_calls += 1
            if RE_TIMEBASE.search(line):
                f.timebase = True
            if RE_LOCK.search(line):
                f.global_lock = True
            if RE_STORE.search(line):
                f.stores += 1
            if RE_LOAD.search(line):
                f.loads += 1
            if RE_LABEL.match(line):
                f.labels += 1
            m = RE_CALL.match(line)
            if m and m.group(1).startswith("__imp__"):
                f.imports += 1
            mm = RE_MNEMONIC.match(line)
            if mm:
                mnem = mm.group(1)
                f.mnemonics[mnem] = f.mnemonics.get(mnem, 0) + 1
                if VMX_HINT.search(mnem):
                    f.has_vmx = True
                    if mnem.startswith(("stvl", "stvr", "lvl", "lvr")):
                        f.unaligned_vstores += 1
                elif FLOAT_HINT.match(mnem):
                    f.float_ops += 1
        return f

    # ------------------------------------------------------------- collapse
    def collapse(self, addr: int, max_lines: int = 0) -> str:
        """Compact rendering: the asm, with the lifter's C++ folded away.

        A 429-line lifted body becomes roughly its instruction count, which is
        what a reader (or a model) actually needs. Prologue and epilogue
        register spills are dropped: they are frame bookkeeping, never ported.
        """
        body = self.body(addr)
        if not body:
            return ""
        names = self.names()
        out: list[str] = []
        for line in body.splitlines():
            label = RE_LABEL.match(line)
            if label:
                out.append(f"{label.group(1)}:")
                continue
            m = RE_MNEMONIC.match(line)
            if not m:
                continue
            mnem, args = m.group(1), (m.group(2) or "").strip()
            if mnem in ("mflr", "mtlr"):
                continue
            if mnem.startswith("b") and args.startswith("0x"):
                # Name the branch target: `bl __imp__RtlEnterCriticalSection`
                # says something; `bl 0x82f52114` costs the reader a lookup.
                try:
                    target = int(args.split()[0], 16)
                except ValueError:
                    target = None
                if target is not None:
                    symbol = names.get(target)
                    if symbol and symbol.startswith(("__savegprlr", "__restgprlr",
                                                     "__savefpr", "__restfpr",
                                                     "__savevmx", "__restvmx")):
                        continue  # frame bookkeeping; never ported
                    if symbol:
                        args = symbol
            out.append(f"  {mnem} {args}".rstrip())
        if max_lines and len(out) > max_lines:
            out = _elide_middle(out, max_lines)
        return "\n".join(out)


def _elide_middle(lines: list[str], max_lines: int) -> list[str]:
    """Keep the head and tail of a listing, marking what was dropped.

    One line of the budget pays for the marker; the rest splits two-thirds head,
    one-third tail, because a function's opening says more about what it does
    than its epilogue does.
    """
    if max_lines <= 1:
        return [f"  ... {len(lines)} instructions elided ..."]
    budget = max_lines - 1
    head_n = max(1, (budget * 2) // 3)
    tail_n = max(0, budget - head_n)
    dropped = len(lines) - head_n - tail_n
    if dropped <= 0:
        return lines
    marker = f"  ... {dropped} instructions elided ..."
    tail = lines[len(lines) - tail_n:] if tail_n else []
    return lines[:head_n] + [marker] + tail


def _make_callee(addr: int | None, name: str, line: int) -> Callee:
    if not name:
        return Callee(addr, f"sub_{addr:08X}" if addr else "?", "unresolved", line)
    if name.startswith("__imp__"):
        return Callee(addr, name, "import", line)
    if name.startswith("__"):
        return Callee(addr, name, "helper", line)
    return Callee(addr, name, "direct", line)


def from_project(project: "Project") -> RexGlueLifted:
    """Build the adapter for a project.

    The directory actually imported wins over configuration: `decomp import
    lifted <dir>` records where the corpus came from, and later stages must read
    the same tree rather than whatever the config file happens to say.
    """
    generated = (
        project.db.meta_get(INDEX_META_KEY.replace(".index", ".dir"))
        or project.db.meta_get("truth.lifted_dir")
        or project.get("target.lifted_dir")
        or project.get("truth.generated_dir")
    )
    if not generated:
        recomp = project.get("target.recomp_path")
        if recomp:
            generated = str(Path(recomp) / "generated")
    if not generated:
        raise KeyError(
            "no lifted corpus known: run `decomp import lifted <dir>`, "
            "or set target.lifted_dir in decomp.toml"
        )
    pattern = (
        project.db.meta_get("truth.lifted_pattern")
        or project.get("truth.pattern")
        or "*_recomp.*.cpp"
    )
    return RexGlueLifted(
        generated,
        pattern=pattern,
        cache_path=project.state / "cache" / "lifted_index.json",
    )
