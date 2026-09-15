"""Driving a decompiler.

One long-lived process, not one per call. Ghidra's JVM takes a couple of seconds
to start and its analysis is expensive; the audio project got 1,536 functions in
about a minute by importing once with analysis off and decompiling known entry
points, rather than letting it analyse an 18 MB image it had already been told
the answers about.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class DecompResult:
    addr: int
    ok: bool
    c: str = ""
    signature: str = ""
    callees: list[int] = field(default_factory=list)
    error: str = ""
    duration_ms: int = 0

    def brief(self) -> str:
        state = "ok" if self.ok else f"failed: {self.error[:60]}"
        return f"sub_{self.addr:08X}\t{state}\t{len(self.c)} chars"


@dataclass
class EngineInfo:
    id: str
    version: str = ""
    program: str = ""
    language: str = ""
    functions: int = 0
    analysis: bool = False

    def brief(self) -> str:
        return (
            f"{self.id}\t{self.version}\t{self.program}\t{self.language}"
            f"\t{self.functions} functions"
        )


class AnalysisEngine(Protocol):
    id: str

    def open(self, image: str, base: int, language: str, project_dir: str,
             analyze: bool = False) -> EngineInfo:
        ...

    def define_functions(self, addrs: list[int]) -> int:
        ...

    def apply_names(self, names: dict[int, str]) -> int:
        ...

    def fix_helpers(self, prefixes: list[str]) -> int:
        ...

    def decompile(self, addr: int, timeout_s: int = 60) -> DecompResult:
        ...

    def close(self) -> None:
        ...
