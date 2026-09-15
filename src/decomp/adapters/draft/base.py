"""Producing a candidate port without asking a model.

The cheapest token is the one never spent. A large share of any corpus is
thunks, getters, setters and register shuffles whose translation is entirely
mechanical, and handing those to a model is paying for judgment where none is
required.

A drafter must refuse rather than guess. A partial translation that compiles is
worse than no draft at all: it reaches a session, diverges, and costs a retry
plus the session it wasted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class Draft:
    addr: int
    code: str
    windows: list[dict] = field(default_factory=list)
    result_registers: list[str] = field(default_factory=list)
    note: str = ""
    source: str = "mechanical"
    confidence: float = 1.0

    def brief(self) -> str:
        return (
            f"sub_{self.addr:08X}\t{self.source}\t{len(self.code.splitlines())} lines"
            f"\t{len(self.windows)} window(s)"
        )


@dataclass
class DraftRefusal:
    addr: int
    reason: str

    def brief(self) -> str:
        return f"sub_{self.addr:08X}\tno draft\t{self.reason}"


class Drafter(Protocol):
    id: str

    def draft(self, addr: int, body: str, context: dict) -> Draft | DraftRefusal:
        ...
