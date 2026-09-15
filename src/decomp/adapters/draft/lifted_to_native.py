"""Translate a lifted function into readable native C++, without a model.

The lifted form is one statement per machine instruction against a register
context. This rewrites it into named locals and typed memory access, which is
the same transformation a person would make by hand for a simple function.

It is a translation, not a copy. Emitting the lifted body verbatim would pass
any comparison trivially and prove nothing about either the port or the oracle,
so the output has to differ in form while matching in behaviour.

The grammar it understands is small on purpose. Anything outside it is refused,
because a draft that is nearly right costs a session to discover.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .base import Draft, Drafter, DraftRefusal


def _reg(name: str) -> str:
    """A named capture for one register reference."""
    return rf"ctx\.(?P<{name}>r\d+)\.(?:u32|u64|s32|s64)"


WIDTH = r"(?P<width>U8|U16|U32|U64|F32|F64)"

# Every shape the translator recognises. Named groups throughout: mixing named
# and numbered groups silently renumbers the positional ones, which produced
# `ctx.U32.u32` in the first version of this file.
PATTERNS = (
    ("load", re.compile(
        rf"^{_reg('dest')}\s*=\s*REX_LOAD_{WIDTH}\s*\(\s*"
        rf"{_reg('base')}\s*(?:\+\s*(?P<off>-?\w+))?\s*\)\s*;$")),
    ("store", re.compile(
        rf"^REX_STORE_{WIDTH}\s*\(\s*{_reg('base')}\s*"
        rf"(?:\+\s*(?P<off>-?\w+))?\s*,\s*(?P<value>[^)]+?)\s*\)\s*;$")),
    ("immediate", re.compile(
        rf"^{_reg('dest')}\s*=\s*(?P<imm>-?(?:0x)?[0-9A-Fa-f]+)\s*;$")),
    ("move", re.compile(rf"^{_reg('dest')}\s*=\s*{_reg('src')}\s*;$")),
    ("arith", re.compile(
        rf"^{_reg('dest')}\s*=\s*{_reg('src')}\s*(?P<op>[-+|&^])\s*"
        rf"(?P<rhs>[^;]+?)\s*;$")),
    ("return", re.compile(r"^return\s*;$")),
    ("scratch", re.compile(r"^PPCRegister\s+\w+\s*\{\s*\}\s*;$")),
    ("link", re.compile(rf"^{_reg('dest')}\s*=\s*ctx\.lr\s*;$")),
    # Anything else that only computes over registers. The expression is kept as
    # the lifter wrote it: the value of this rewrite is in the memory access and
    # the naming, not in re-deriving a rotate mask by hand.
    ("compute", re.compile(
        rf"^{_reg('dest')}\.?\w*\s*=\s*(?P<expr>[^;]+)\s*;$")),
    ("effect", re.compile(r"^ctx\.(?:cr\d+|fpscr|xer)\.[^;]+;$")),
)

# An expression touching any of these is not register-only, so it is not safe to
# pass through unexamined.
RE_NOT_PURE = re.compile(
    r"REX_(?:MM_)?(?:LOAD|STORE)_|GuestCall|sub_[0-9A-Fa-f]{8}|__imp__|"
    r"REX_CALL|REX_QUERY"
)

RE_COMMENT = re.compile(r"^//\s*(?P<mnemonic>.+)$")
RE_PROLOGUE = re.compile(r"^(?:REX_FUNC_PROLOGUE\s*\(\s*\)\s*;|uint32_t\s+ea\{\}\s*;)$")
RE_DEFINE = re.compile(r"^DEFINE_REX_FUNC\(sub_[0-9A-Fa-f]{8}\)\s*\{$")

# Argument registers, which is what a window may be rooted at.
ENTRY_REGS = tuple(f"r{n}" for n in range(3, 11))
WIDTH_TYPES = {
    "U8": "uint8_t", "U16": "uint16_t", "U32": "uint32_t", "U64": "uint64_t",
    "F32": "float", "F64": "double",
}
WIDTH_BYTES = {"U8": 1, "U16": 2, "U32": 4, "U64": 8, "F32": 4, "F64": 8}


@dataclass
class _State:
    lines: list[str]
    windows: list[dict]
    names: dict[str, str]          # register -> local name
    stores: int = 0
    loads: int = 0
    computed: int = 0
    writes_r3: bool = False


class LiftedToNative(Drafter):
    id = "lifted_to_native"

    # Raising this past ~48 gains almost nothing: what limits coverage is
    # unrecognised constructs, not length. Measured on a 612-function corpus,
    # 24 gives 82 drafts and 200 gives 85.
    def __init__(self, max_instructions: int = 48):
        self.max_instructions = max_instructions

    def draft(self, addr: int, body: str, context: dict | None = None):
        context = context or {}
        if context.get("gate"):
            return DraftRefusal(addr, f"gated ({context['gate']})")
        if context.get("has_vmx"):
            return DraftRefusal(addr, "vector arithmetic needs a reader, not a rewriter")

        statements = _statements(body)
        if not statements:
            return DraftRefusal(addr, "no body")

        # Translate first, then apply the length limit. Checking length up front
        # reported "too long" for functions that would have hit an unrecognised
        # construct anyway, which named the wrong constraint: on the hottest 200
        # functions, raising the limit from 48 to 2000 changed coverage not at
        # all. Translation is cheap and refuses safely, so attempting it costs
        # nothing and the refusal it reports is the real one.
        state = _State(lines=[], windows=[], names={})
        for mnemonic, statement in statements:
            handled = self._translate(statement, mnemonic, state)
            if not handled:
                # A draft that is nearly right costs a session to discover.
                return DraftRefusal(addr, f"unrecognised: {statement[:60]}")

        if len(statements) > self.max_instructions:
            return DraftRefusal(
                addr,
                f"{len(statements)} instructions exceeds the mechanical limit: "
                f"it translates, but a body this long is worth a reader",
            )

        if not state.stores and not state.writes_r3:
            return DraftRefusal(addr, "nothing observable to compare")

        result_registers = ["r3"] if state.writes_r3 else []
        note = (
            f"Mechanical translation: {state.loads} load(s), {state.stores} store(s)"
            + (f", {state.computed} register expression(s) kept as lifted."
               if state.computed else ".")
        )
        return Draft(
            addr=addr, code="\n".join(state.lines), windows=state.windows,
            result_registers=result_registers, note=note,
        )

    # ------------------------------------------------------------ translate
    def _translate(self, statement: str, mnemonic: str, state: _State) -> bool:
        for kind, pattern in PATTERNS:
            m = pattern.match(statement)
            if not m:
                continue
            if kind == "compute" and RE_NOT_PURE.search(statement):
                # Touches memory or another function: not a pure computation,
                # and passing it through unexamined would be a guess.
                return False
            handler = getattr(self, f"_do_{kind}")
            handler(m, mnemonic, state)
            return True
        return False

    def _local(self, reg: str, state: _State) -> str:
        """A readable name for a register's current value."""
        if reg in state.names:
            return state.names[reg]
        if reg in ENTRY_REGS:
            index = ENTRY_REGS.index(reg)
            name = f"arg{index}"
            state.names[reg] = name
            state.lines.insert(
                len([ln for ln in state.lines if ln.startswith("const uint32_t arg")]),
                f"const uint32_t {name} = ctx.{reg}.u32;  // {reg}",
            )
            return name
        return f"ctx.{reg}.u32"

    def _do_load(self, m, mnemonic, state: _State) -> None:
        dest, base = m.group("dest"), m.group("base")
        width = m.group("width")
        offset = m.group("off") or "0"
        base_name = self._local(base, state)
        name = f"v{dest[1:]}"
        state.names[dest] = name
        ctype = WIDTH_TYPES[width]
        state.lines.append(
            f"const {ctype} {name} = REX_LOAD_{width}({base_name} + {offset});"
            f"  // {mnemonic}"
        )
        state.loads += 1

    def _do_store(self, m, mnemonic, state: _State) -> None:
        base = m.group("base")
        width = m.group("width")
        offset = m.group("off") or "0"
        value = m.group("value")
        base_name = self._local(base, state)
        value_name = self._value(value, state)
        state.lines.append(
            f"REX_STORE_{width}({base_name} + {offset}, {value_name});  // {mnemonic}"
        )
        state.stores += 1
        if base in ENTRY_REGS:
            try:
                numeric = int(offset, 0)
            except ValueError:
                numeric = 0
            state.windows.append(
                {"base": base, "offset": numeric, "length": WIDTH_BYTES[width],
                 "why": mnemonic[:60]}
            )

    def _do_immediate(self, m, mnemonic, state: _State) -> None:
        dest, imm = m.group("dest"), m.group("imm")
        name = f"v{dest[1:]}"
        state.names[dest] = name
        state.lines.append(f"const uint32_t {name} = {imm};  // {mnemonic}")
        if dest == "r3":
            state.writes_r3 = True
            state.lines.append(f"ctx.r3.s64 = {imm};")

    def _do_move(self, m, mnemonic, state: _State) -> None:
        dest, src = m.group("dest"), m.group("src")
        name = self._local(src, state)
        state.names[dest] = name
        if dest == "r3":
            state.writes_r3 = True
            state.lines.append(f"ctx.r3.u32 = {name};  // {mnemonic}")

    def _do_arith(self, m, mnemonic, state: _State) -> None:
        dest, src = m.group("dest"), m.group("src")
        op, rhs = m.group("op"), m.group("rhs")
        left = self._local(src, state)
        right = self._value(rhs, state)
        name = f"v{dest[1:]}"
        state.names[dest] = name
        # Kept 64-bit: a truncated chain can leave memory identical and still
        # return the wrong register, which surfaces only on a later call.
        state.lines.append(
            f"const uint64_t {name} = (uint64_t){left} {op} (uint64_t){right};"
            f"  // {mnemonic}"
        )
        if dest == "r3":
            state.writes_r3 = True
            state.lines.append(f"ctx.r3.u64 = {name};")

    def _do_scratch(self, m, mnemonic, state: _State) -> None:
        """A scratch register declaration carries no behaviour."""
        return

    def _do_link(self, m, mnemonic, state: _State) -> None:
        """Reading the link register is frame bookkeeping, never ported."""
        return

    def _do_effect(self, m, mnemonic, state: _State) -> None:
        """Condition-register and status updates.

        The harness compares only what a caller reads, and a condition register
        set inside a body is consumed inside it. Emitted verbatim so any
        following branch still sees it.
        """
        state.lines.append(f"{m.group(0)}  // {mnemonic}")

    def _do_compute(self, m, mnemonic, state: _State) -> None:
        dest, expr = m.group("dest"), m.group("expr").strip()
        rewritten = self._rename_registers(expr, state)
        name = f"v{dest[1:]}"
        state.names[dest] = name
        state.lines.append(f"const uint64_t {name} = {rewritten};  // {mnemonic}")
        state.computed += 1
        if dest == "r3":
            state.writes_r3 = True
            state.lines.append(f"ctx.r3.u64 = {name};")

    def _rename_registers(self, expr: str, state: _State) -> str:
        """Substitute named locals for registers already bound."""
        def replace(match: re.Match) -> str:
            reg = match.group("r")
            local = state.names.get(reg)
            return local if local else match.group(0)

        return re.sub(_reg("r") + r"(?![\w.])", replace, expr)

    def _do_return(self, m, mnemonic, state: _State) -> None:
        """The lifted form's trailing return. The harness's wrapper supplies it,
        so nothing is emitted here."""
        return

    def _value(self, expr: str, state: _State) -> str:
        expr = expr.strip()
        m = re.match(rf"^{_reg('r')}$", expr)
        if m:
            reg = m.group("r")
            return state.names.get(reg, f"ctx.{reg}.u32")
        return expr


def _statements(body: str) -> list[tuple[str, str]]:
    """(mnemonic, statement) pairs, with the wrapper and frame setup removed."""
    out: list[tuple[str, str]] = []
    pending = ""
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line == "}" or RE_DEFINE.match(line) or RE_PROLOGUE.match(line):
            continue
        comment = RE_COMMENT.match(line)
        if comment:
            pending = comment.group("mnemonic").strip()
            continue
        out.append((pending, line))
        pending = ""
    return out
