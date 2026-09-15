"""Terse output. Every stage result renders to a few lines, not a wall of text.

The user runs everything through `rtk`, a token-filtering proxy. Harness output
should already be that small.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from dataclasses import asdict, is_dataclass
from typing import Any

_JSON_MODE = False


def set_json(enabled: bool) -> None:
    global _JSON_MODE
    _JSON_MODE = enabled


def is_json() -> bool:
    return _JSON_MODE


def emit(result: Any) -> None:
    """Print a stage result: JSON when --json, else its brief() or str()."""
    if _JSON_MODE:
        print(json.dumps(_jsonable(result), default=str))
        return
    if hasattr(result, "brief"):
        text = result.brief()
    elif isinstance(result, str):
        text = result
    else:
        text = str(result)
    if text:
        print(text)


def _jsonable(obj: Any) -> Any:
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: _jsonable(v) for k, v in asdict(obj).items()}
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    return obj


def table(rows: Sequence[Sequence[Any]], headers: Sequence[str] | None = None) -> str:
    """Tab-separated table. No box drawing, no padding waste."""
    lines = []
    if headers:
        lines.append("\t".join(str(h) for h in headers))
    for r in rows:
        lines.append("\t".join("" if c is None else str(c) for c in r))
    return "\n".join(lines)


def warn(msg: str) -> None:
    print(f"warn: {msg}", file=sys.stderr)


def fail(msg: str, code: int = 1) -> None:
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(code)
