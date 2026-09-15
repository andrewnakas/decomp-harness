"""What is being reverse engineered.

A target answers three questions: what bytes are we analysing, where do they
live in the address space, and where do its functions start. The third is the
one that matters most. The audio project decompiled 1,536 functions in about a
minute by telling the decompiler exactly where to look, rather than letting it
analyse an 18 MB image it had already been told the answers about.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol


@dataclass
class TargetImage:
    """The bytes, and where they sit."""

    path: Path
    base: int = 0
    arch: str = ""
    endian: str = "big"
    ptr_size: int = 4
    ghidra_lang: str = ""
    platform: str = "generic"
    size: int = 0
    sha256: str = ""
    notes: list[str] = field(default_factory=list)

    def brief(self) -> str:
        return (
            f"{self.path.name}\t{self.size} bytes\t0x{self.base:08X}"
            f"\t{self.arch} {self.endian}-endian"
        )


class TargetLoader(Protocol):
    id: str

    def detect(self, path: Path) -> bool:
        """Does this loader recognise the file?"""
        ...

    def load(self, path: Path, config: dict) -> TargetImage:
        ...

    def entry_points(self, image: TargetImage) -> list[int]:
        """Known function starts, if the format or a sibling artifact carries them.

        Empty is an honest answer: it means the engine will have to find them,
        or another source will supply them.
        """
        ...

    def helper_prefixes(self) -> list[str]:
        """Register save and restore stubs, which a decompiler must be told about."""
        ...
