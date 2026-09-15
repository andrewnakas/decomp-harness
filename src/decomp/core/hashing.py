"""Content hashing for idempotent stages and cache keys."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(chunk):
            h.update(block)
    return h.hexdigest()


def sha256_files(paths: Iterable[Path]) -> str:
    """Hash a set of files by (relative name, content hash), order-independent."""
    parts = sorted(f"{p.name}:{sha256_file(p)}" for p in paths if p.is_file())
    return sha256_text("\n".join(parts))


def dir_signature(root: Path, pattern: str = "*") -> str:
    """Cheap signature of a directory: names + sizes + mtimes. Avoids reading 289 MB."""
    if not root.is_dir():
        return "missing"
    parts = []
    for p in sorted(root.rglob(pattern)):
        if p.is_file():
            st = p.stat()
            parts.append(f"{p.relative_to(root)}:{st.st_size}:{int(st.st_mtime)}")
    return sha256_text("\n".join(parts))


def stable_hash(obj: Any) -> str:
    """Hash any JSON-able structure deterministically."""
    return sha256_text(json.dumps(obj, sort_keys=True, default=str))
