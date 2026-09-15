"""The cached prefix: the part of every call that does not change.

Both providers charge a fraction for input they have already seen. Measured on
this machine, a first call paid $0.0278 and the identical second call paid
$0.0034, because the prompt was byte-for-byte the same. That is the entire
argument for keeping this stable: the rules, the macro reference, and the
recovered layouts are sent once per hour and every packet after that rides free.

So the prefix must not vary with the function being ported. Anything
function-specific belongs in the packet.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..core.hashing import sha256_text
from ..core.tokens import estimate

if TYPE_CHECKING:
    from ..core.config import Project

PORT_RULES = """\
You are porting one guest function to native C++ inside a static recompilation.

Reproduce the original exactly, bugs included. A port that improves on the
original is wrong: it will be compared against the original's own behaviour, and
a fix reads as a divergence.

Rules that have each cost this project a session:

- Preserve store order. Do not hoist a load across a store that could alias it.
  If the original reloads a value after storing it, reload it too.
- Keep 64-bit intermediates through an arithmetic chain and cast only at the
  store. The lifted form's add and mullw are 64-bit on zero-extended operands,
  so a sum carries into bit 32. A truncated chain can leave memory identical and
  still return the wrong register, which surfaced once only on the 120th call.
- Compute constant addresses arithmetically: ((imm & 0xFFFF) << 16) + offset.
  Never read one by eye. A single misread digit produced this project's first
  divergence.
- Match access widths exactly: u8, u16, u32, u64, and the float round trips.
  A single-precision store followed by a load is not a no-op.
- Decompiled pointer arithmetic is scaled by the pointer's type. If `p` is a
  u32* then `p + 1` is four bytes along, not one. Convert to a byte offset
  before you write it, and say the byte offset in the window.
- Use fused multiply-add only where the original line is fmadd or fmsub. Vector
  multiply-add stays a multiply and an add: two roundings, not one.
- Never call an import directly. Call through the guest-call helper so the
  context is threaded.
- Do not clobber callee-saved registers, and do not reproduce the prologue: the
  frame is not yours to manage and is never compared.
- Cite the mnemonic in a comment on every store and every branch, the way the
  lifted form does.

Windows are the other half of the answer. Declare every span the body writes,
including writes made by anything it calls, and exclude the function's own
frame. The harness rewinds exactly what you declare before running your code, so
a write outside your windows is never undone and reaches the running program.
An incomplete window set is not a smaller answer, it is a wrong one.

If the write set cannot be known from the entry state, say so with `blocked`
rather than guessing. A function honestly marked unverifiable is worth more than
one that passes a comparison covering a third of its calls.

If you need something the packet does not contain, ask for it with `needs`
instead of assuming. The harness will supply it and ask again.
"""

MACRO_REFERENCE = """\
Reference for the body you write:

  ctx.rN.u32 / .u64 / .s32 / .s64   general registers
  ctx.fN.f64                        floating registers
  ctx.vN                            vector registers
  REX_LOAD_U8/U16/U32/U64(addr)     guest memory reads
  REX_LOAD_F32/F64(addr)
  REX_STORE_U8/U16/U32/U64(addr,v)  guest memory writes
  REX_STORE_F32/F64(addr,v)
  GuestCall(ctx, base, sub_XXXXXXXX)  call another guest function

Guest addresses are 32-bit and big-endian. Write statements only: the harness
wraps them in the namespace, the function signature and the registration macro.
"""


@dataclass
class Prefix:
    text: str
    tokens: int
    hash: str
    sections: dict[str, int]

    def brief(self) -> str:
        parts = " ".join(f"{k}={v}" for k, v in self.sections.items())
        return f"prefix\t{self.tokens} tok\t{self.hash[:12]}\t{parts}"


def build(project: Project, subsystem: str = "",
          include_layouts: bool = True, max_layout_tokens: int = 2000) -> Prefix:
    """Assemble the stable prefix for a run."""
    sections: dict[str, int] = {}
    parts: list[str] = []

    target = project.target_row() or {}
    facts = _target_facts(project, target)
    parts.append(facts)
    sections["target"] = estimate(facts)

    parts.append(PORT_RULES)
    sections["rules"] = estimate(PORT_RULES)

    parts.append(MACRO_REFERENCE)
    sections["macros"] = estimate(MACRO_REFERENCE)

    if include_layouts:
        layouts = _layouts(project, max_layout_tokens)
        if layouts:
            parts.append(layouts)
            sections["layouts"] = estimate(layouts)

    lessons = _lessons(project)
    if lessons:
        parts.append(lessons)
        sections["lessons"] = estimate(lessons)

    text = "\n\n".join(parts)
    return Prefix(
        text=text, tokens=estimate(text), hash=sha256_text(text), sections=sections
    )


def _target_facts(project: Project, target: dict) -> str:
    arch = target.get("arch") or project.get("target.arch", "")
    endian = target.get("endian") or project.get("target.endian", "big")
    platform = target.get("platform") or project.get("target.platform", "")
    ptr = target.get("ptr_size") or project.get("target.ptr_size", 4)
    lines = ["Target:"]
    if platform:
        lines.append(f"  platform: {platform}")
    lines.append(f"  architecture: {arch}, {endian}-endian, {ptr * 8}-bit pointers")
    base = target.get("base_addr")
    if base:
        lines.append(f"  image base: 0x{base:08X}")
    return "\n".join(lines)


def _layouts(project: Project, max_tokens: int) -> str:
    """Recovered struct layouts, as a header the model can read at a glance.

    Only established fields appear. A proposed field is a hypothesis, and
    printing it beside confirmed ones would launder it into a fact.
    """
    structs = project.db.query(
        "SELECT id, name, size FROM struct ORDER BY name"
    )
    if not structs:
        return ""
    out: list[str] = ["Recovered layouts (established fields only):"]
    for s in structs:
        fields = project.db.query(
            "SELECT offset, size, ctype, name FROM struct_field "
            "WHERE struct_id=? AND status IN ('established','confirmed') "
            "ORDER BY offset",
            (s["id"],),
        )
        if not fields:
            continue
        size = f" /* 0x{s['size']:X} */" if s.get("size") else ""
        out.append(f"  {s['name']}{size}")
        for f in fields:
            out.append(
                f"    +0x{f['offset']:03X}  {(f['ctype'] or 'u32'):<10} {f['name']}"
            )
        if estimate("\n".join(out)) > max_tokens:
            out.append("    ... (further layouts omitted for size)")
            break
    return "\n".join(out)


def _lessons(project: Project) -> str:
    """Traps that apply while writing a port.

    Only the port-stage ones: a lesson about build scripts is true, but it is
    the harness's job, not the model's, and it would cost tokens on every call.
    """
    rows = project.db.query(
        "SELECT title, body FROM lesson WHERE trigger='port' ORDER BY id"
    )
    if not rows:
        return ""
    out = ["Also:"]
    for r in rows:
        out.append(f"  {r['title']}. {r['body']}")
    return "\n".join(out)
