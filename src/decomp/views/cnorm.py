"""Normalize decompiler C so a packet carries meaning instead of noise.

Ghidra's output is correct and verbose. It spends tokens on `undefined4`, on a
declaration block whose types say nothing, and on raw hex offsets that a reader
has to look up. None of that is information the model needs to be told twice.

Substitution is deliberately conservative. Rewriting `*(int *)(iVar2 + 0x150)`
into `player->format_index` requires knowing what iVar2 points to, and a wrong
guess there is worse than no guess: it states a fact the harness has not
established. So offsets are annotated, not rewritten, and the annotation names
the struct it came from.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Ghidra's placeholder types carry no information beyond their width.
TYPE_MAP = {
    "undefined8": "u64",
    "undefined4": "u32",
    "undefined2": "u16",
    "undefined1": "u8",
    "undefined": "u8",
    "ulonglong": "u64",
    "longlong": "i64",
    "uint3": "u32",
    "uint": "u32",
    "ushort": "u16",
    "byte": "u8",
    "code": "void",
}

RE_DECL = re.compile(
    r"^\s*(?:"
    + "|".join(re.escape(t) for t in sorted(TYPE_MAP, key=len, reverse=True))
    + r"|int|char|float|double|short|long|bool)\s*\**\s*[A-Za-z_]\w*\s*(?:\[[^\]]*\])?\s*;\s*$"
)
RE_OFFSET = re.compile(r"\+\s*(0x[0-9A-Fa-f]+|\d+)\s*\)")
# The decompiler gave up entirely: the body is not C, it is a stub.
RE_FAILED = re.compile(r"\bhalt_baddata\b")
# The body is real C but some branch target is unnamed. Usable, worth noting.
RE_UNRESOLVED_BRANCH = re.compile(r"\bcode_r0x|\bUNRECOVERED_JUMPTABLE\b|\bswitchD\b")
RE_SIGNATURE = re.compile(r"^\s*[\w *]+\s+(\w+)\s*\(")


@dataclass
class NormalizedView:
    text: str
    original_chars: int
    offsets_seen: list[int] = field(default_factory=list)
    dropped_decls: int = 0
    unresolved: bool = False

    @property
    def chars(self) -> int:
        return len(self.text)

    @property
    def reduction(self) -> float:
        if not self.original_chars:
            return 0.0
        return 1.0 - (self.chars / self.original_chars)

    def brief(self) -> str:
        return (
            f"{self.original_chars} -> {self.chars} chars "
            f"({self.reduction:.0%} smaller), {self.dropped_decls} decls dropped"
        )


def normalize(source: str, field_names: dict[int, str] | None = None,
              drop_declarations: bool = True) -> NormalizedView:
    """Rewrite decompiler C into its informative core.

    `field_names` maps a byte offset to a recovered field name. Matching offsets
    gain a trailing comment naming the field; the expression itself is untouched,
    because the harness does not know which pointer each offset belongs to.
    """
    field_names = field_names or {}
    original = len(source)
    out: list[str] = []
    dropped = 0
    offsets: list[int] = []
    unresolved = bool(RE_UNRESOLVED_BRANCH.search(source))

    for raw in source.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if drop_declarations and RE_DECL.match(line):
            dropped += 1
            continue

        for ghidra_type, short in TYPE_MAP.items():
            line = re.sub(rf"\b{ghidra_type}\b", short, line)

        annotations: list[str] = []
        for m in RE_OFFSET.finditer(line):
            try:
                value = int(m.group(1), 0)
            except ValueError:
                continue
            offsets.append(value)
            name = field_names.get(value)
            if name and name not in annotations:
                annotations.append(name)

        if annotations:
            line = f"{line}  // {', '.join(annotations)}"
        out.append(line)

    text = "\n".join(out)
    return NormalizedView(
        text=text,
        original_chars=original,
        offsets_seen=sorted(set(offsets)),
        dropped_decls=dropped,
        unresolved=unresolved,
    )


def signature_of(source: str) -> str:
    """The function's declared prototype, as the decompiler recovered it."""
    for line in source.splitlines():
        line = line.strip()
        if not line or line.startswith(("/*", "//", "{")):
            continue
        m = RE_SIGNATURE.match(line)
        if m:
            return line.rstrip("{").strip()
        break
    return ""


def is_usable(source: str) -> bool:
    """Did the decompiler actually recover this function?

    Only halt_baddata means it gave up: Ghidra's PowerPC models do not decode
    Xenon's vector ISA, so those come back as a stub and the lifted form is the
    authority. An unnamed branch target (code_r0x...) is not a failure - the
    body is real C - and treating it as one would push 186 of this corpus's
    1,694 functions onto the expensive path for no reason.
    """
    if not source.strip():
        return False
    return not RE_FAILED.search(source)


def has_unresolved_branch(source: str) -> bool:
    """Usable C, but with a branch target the decompiler could not name."""
    return bool(RE_UNRESOLVED_BRANCH.search(source))
