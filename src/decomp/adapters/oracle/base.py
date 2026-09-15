"""Deciding whether a port is right.

An oracle answers one question: does this candidate behave like the original?
The harness does not care how, and four answers are equally valid:

  shadow        run both against the same state and compare registers and memory
  byte match    compile the candidate and compare the object, symbol by symbol
  differential  run both under an emulator on recorded or synthesized inputs
  replay        re-run recorded call vectors against a port in another language

They are peers. A project may have more than one, and a function that passes two
is better evidenced than one that passes either. What they share is the contract
below, and one rule that is not negotiable: an oracle must be able to fail. A
comparison that cannot disagree has not verified anything, so every oracle
supplies a way to build a candidate that is deliberately wrong, and the harness
requires that one to be caught before it records anything else.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

# What an oracle can conclude about one function.
VERIFIED = "verified"      # compared, and never disagreed
DIVERGED = "diverged"      # compared, and disagreed
UNCALLED = "uncalled"      # never exercised, so nothing was compared
SKIPPED = "skipped"        # the oracle declined to compare these calls
OVERFLOW = "overflow"      # the comparison did not fit its budget
PARTIAL = "partial"        # compared on some paths only


@dataclass
class OraclePlan:
    """What has to happen before a comparison can run."""

    candidates: list[int] = field(default_factory=list)
    controls: list[int] = field(default_factory=list)
    needs_build: bool = True
    notes: list[str] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        """A plan with no control cannot produce a trustworthy result."""
        return bool(self.candidates) and bool(self.controls)


@dataclass
class OracleRun:
    """One execution of the oracle."""

    id: str
    ok: bool = False
    host: str = "local"
    duration_s: float = 0.0
    log_path: str = ""
    detail: dict[str, Any] = field(default_factory=dict)
    error: str = ""


@dataclass
class OracleVerdict:
    addr: int
    result: str
    compared: int = 0
    skipped: int = 0
    detail: str = ""

    @property
    def conclusive(self) -> bool:
        """Did this actually compare anything?

        A clean report over zero comparisons is the shape of a run that looks
        green and proved nothing.
        """
        return self.compared > 0 and self.result in (VERIFIED, DIVERGED, PARTIAL)


class Oracle(Protocol):
    id: str
    kind: str          # shadow | bytematch | differential | replay

    def prepare(self, candidates: list[int]) -> OraclePlan:
        """What to build and arm, including the controls."""
        ...

    def run(self, plan: OraclePlan, transport, **options: Any) -> OracleRun:
        ...

    def verdicts(self, run: OracleRun) -> list[OracleVerdict]:
        ...

    def divergence_fragment(self, verdict: OracleVerdict, max_tokens: int = 400) -> str:
        """What to send back on a retry: the disagreement, not the log."""
        ...
