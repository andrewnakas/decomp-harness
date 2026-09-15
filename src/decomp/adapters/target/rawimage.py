"""A flat image loaded at a fixed address.

The common case for console work: a decrypted executable already stripped of its
container, with the load address known from somewhere else.
"""

from __future__ import annotations

from pathlib import Path

from ...core.hashing import sha256_file
from .base import TargetImage, TargetLoader

# Xenon and Cell prologues call these to save and restore callee-saved
# registers. A decompiler that models them as ordinary functions loses the first
# argument, and every struct offset read from the result is wrong.
PPC_HELPER_PREFIXES = (
    "__savegprlr_", "__restgprlr_",
    "__savefpr_", "__restfpr_",
    "__savevmx_", "__restvmx_",
)


class RawImageLoader(TargetLoader):
    id = "rawimage"

    def detect(self, path: Path) -> bool:
        """Anything, which is why this loader is the fallback and never the guess."""
        return path.is_file()

    def load(self, path: Path, config: dict) -> TargetImage:
        path = Path(path)
        base = config.get("base_addr") or 0
        if isinstance(base, str):
            base = int(base, 0)
        return TargetImage(
            path=path,
            base=base,
            arch=config.get("arch", "ppc64"),
            endian=config.get("endian", "big"),
            ptr_size=int(config.get("ptr_size", 4)),
            ghidra_lang=config.get("ghidra_lang", ""),
            platform=config.get("platform", "generic"),
            size=path.stat().st_size,
            sha256=sha256_file(path),
        )

    def entry_points(self, image: TargetImage) -> list[int]:
        """None from the file itself: a flat image carries no symbol table.

        For a recompiled target the entry points come from the lifted corpus,
        which is a better source anyway.
        """
        return []

    def helper_prefixes(self) -> list[str]:
        return list(PPC_HELPER_PREFIXES)


class XexLoader(RawImageLoader):
    """An Xbox 360 executable, or the decrypted image extracted from one.

    The retail container is encrypted and compressed, so what reaches the
    harness is the decrypted image a recompiler's tooling produced. Detection
    reports the container so the mistake of pointing at the wrong one is caught
    early: a `default.xex` straight from the disc has no usable addresses.
    """

    id = "xex"
    MAGIC = b"XEX2"
    DEFAULT_BASE = 0x82000000

    def detect(self, path: Path) -> bool:
        try:
            with open(path, "rb") as f:
                return f.read(4) == self.MAGIC
        except OSError:
            return False

    def load(self, path: Path, config: dict) -> TargetImage:
        image = super().load(path, config)
        if not image.base:
            image.base = self.DEFAULT_BASE
        image.platform = config.get("platform") or "xbox360"
        image.ghidra_lang = image.ghidra_lang or "PowerPC:BE:64:A2ALT-32addr"
        if self.detect(path):
            image.notes.append(
                "this is still the XEX container: it is encrypted and compressed, "
                "so its addresses are not usable. Extract the decrypted image first."
            )
        return image


class ElfLoader(RawImageLoader):
    """An ELF, which carries its own base address and symbol table."""

    id = "elf"
    MAGIC = b"\x7fELF"

    def detect(self, path: Path) -> bool:
        try:
            with open(path, "rb") as f:
                return f.read(4) == self.MAGIC
        except OSError:
            return False

    def load(self, path: Path, config: dict) -> TargetImage:
        image = super().load(path, config)
        image.notes.append(
            "ELF: the loader reads its own base and sections, so an explicit "
            "base address is usually unnecessary"
        )
        return image


LOADERS: tuple[type[RawImageLoader], ...] = (XexLoader, ElfLoader, RawImageLoader)


def detect(path: Path) -> TargetLoader:
    """Pick a loader by inspecting the file, falling back to the flat reader."""
    path = Path(path)
    for loader_class in LOADERS:
        loader = loader_class()
        if loader.id != "rawimage" and loader.detect(path):
            return loader
    return RawImageLoader()


def get_loader(name: str) -> TargetLoader:
    for loader_class in LOADERS:
        if loader_class.id == name:
            return loader_class()
    return RawImageLoader()
