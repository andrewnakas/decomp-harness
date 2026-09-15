"""Running the program so the oracle can watch it.

A shadow session runs each hooked function twice per call: the original, then
the candidate against rewound memory, then a comparison. Verdicts come from real
inputs the program generates for itself, which is why this beats any test suite
a person would write by hand.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class FunctionVerdict:
    addr: int
    result: str                  # verified|diverged|uncalled|overflow|skipped|census
    calls: int = 0
    compared: int = 0
    skipped: int = 0
    divergence: str = ""

    @property
    def clean(self) -> bool:
        return self.result == "verified" and self.compared > 0

    def brief(self) -> str:
        return (
            f"sub_{self.addr:08X}\t{self.result}\tcompared={self.compared}"
            f"\tskipped={self.skipped}"
            + (f"\t{self.divergence[:80]}" if self.divergence else "")
        )


@dataclass
class SessionRun:
    label: str
    host: str
    profile: str
    log_path: str = ""
    ok: bool = False
    duration_s: float = 0.0
    calls_total: int = 0
    error: str = ""
    raw: str = ""

    def brief(self) -> str:
        state = "ok" if self.ok else f"FAILED {self.error[:60]}"
        return f"session\t{self.label}\t{state}\t{self.calls_total} calls"


@dataclass
class SessionSummary:
    verdicts: list[FunctionVerdict] = field(default_factory=list)
    calls_total: int = 0
    notes: list[str] = field(default_factory=list)

    def by_result(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for v in self.verdicts:
            out[v.result] = out.get(v.result, 0) + 1
        return out


class SessionRunner(Protocol):
    id: str

    def run(self, transport, label: str, profile: str, armed: list[int],
            duration_s: int) -> SessionRun:
        ...

    def summarize(self, run: SessionRun) -> SessionSummary:
        ...
