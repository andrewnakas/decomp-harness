"""Ground truth: the authoritative form of a function when the decompiler's
output is not trustworthy.

For a statically recompiled target that is the lifted C++ (one statement per
machine instruction with the mnemonic in a comment). For a matching-decomp
target it is the original assembly listing. Either way it answers the same
questions: what is the body, what does it call, what constants does it
materialize, and what makes it hard to verify.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class TruthLoc:
    """Where a function's authoritative body lives."""

    addr: int
    path: str
    line: int          # 0-based line of the definition
    lines: int = 0     # body length
    vec: int = 0       # vector instructions seen


@dataclass(frozen=True)
class Callee:
    addr: int | None
    name: str
    kind: str          # direct | indirect | import | helper | unresolved
    site_line: int = 0


@dataclass
class TruthFlags:
    """What the screening gates need to know, computed mechanically."""

    has_vmx: bool = False
    indirect_calls: int = 0
    timebase: bool = False
    global_lock: bool = False
    imports: int = 0
    stores: int = 0
    loads: int = 0
    float_ops: int = 0
    unaligned_vstores: int = 0
    labels: int = 0
    mnemonics: dict[str, int] = field(default_factory=dict)

    def brief(self) -> str:
        bits = []
        if self.has_vmx:
            bits.append("vmx")
        if self.indirect_calls:
            bits.append(f"indirect={self.indirect_calls}")
        if self.timebase:
            bits.append("timebase")
        if self.global_lock:
            bits.append("lock")
        if self.imports:
            bits.append(f"imports={self.imports}")
        bits.append(f"st={self.stores} ld={self.loads}")
        return " ".join(bits)


class GroundTruth(Protocol):
    id: str

    def index(self) -> Mapping[int, TruthLoc]:
        """addr -> location of the authoritative body. Cached; may be large."""
        ...

    def body(self, addr: int) -> str:
        ...

    def callees(self, addr: int) -> list[Callee]:
        ...

    def constants(self, addr: int) -> list[int]:
        """Addresses the function materializes (lis/addi folded arithmetically)."""
        ...

    def flags(self, addr: int) -> TruthFlags:
        ...

    def collapse(self, addr: int, max_lines: int = 0) -> str:
        """A compact, token-cheap rendering of the body."""
        ...
