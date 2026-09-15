"""Gate screening: which functions can be proved equal, and which cannot.

The gates come from the audio project's harness. They are not difficulty
ratings; they say whether an oracle can bracket the function at all:

  gate1  the call reaches something unreplayable on rewound memory: an indirect
         call, a lock, an allocation, a release, a signal
  gate2  the set of bytes it writes cannot be enumerated from its entry state,
         or exceeds the window budget
  gate3  it reads the time base, so two runs legitimately differ
  gate4  it writes nothing the harness can observe (retired once the oracle can
         compare named registers)

Screening is static and costs nothing, which is the point: it removes most of
the corpus from consideration before a single token is spent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class StoreSite:
    """One store, classified by where its base address comes from."""

    line: int
    mnemonic: str
    base: str            # entry | stack | derived | loop | global | unknown
    base_ref: str = ""   # the register or symbol the base came from
    offset: int | None = None
    size: int = 0
    # When the base was loaded from memory: (register, offset) it came from.
    derived_from: tuple[str, int] | None = None

    @property
    def enumerable(self) -> bool:
        """Can this store's address be known before the call runs?"""
        return self.base in ("entry", "stack", "global")


@dataclass
class GateResult:
    addr: int
    gate: str = "pass"                  # pass | gate1 | gate2 | gate3 | gate4
    reasons: list[str] = field(default_factory=list)
    stores: list[StoreSite] = field(default_factory=list)
    suggested_windows: list[dict] = field(default_factory=list)
    census: dict = field(default_factory=dict)

    @property
    def passes(self) -> bool:
        return self.gate == "pass"

    @property
    def gate2_suspects(self) -> int:
        return sum(1 for s in self.stores if not s.enumerable)

    def brief(self) -> str:
        head = f"sub_{self.addr:08X}\t{self.gate}"
        why = "; ".join(self.reasons[:2])
        return f"{head}\t{why}" if why else head


class GateScreener(Protocol):
    id: str
    rules_version: str

    def screen(self, addr: int, body: str) -> GateResult:
        ...
