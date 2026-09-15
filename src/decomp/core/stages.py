"""Idempotent stage runner.

Every pipeline command is a stage: it declares an input hash, and if a previous
run with the same hash succeeded, it is skipped unless --force. This is what
makes `decomp loop` resumable after a kill.
"""

from __future__ import annotations

import functools
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .config import Project


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class StageSkipped:
    stage: str
    inputs_hash: str
    previous: dict[str, Any]

    def brief(self) -> str:
        return f"{self.stage}: skipped (unchanged inputs; --force to rerun)"


class StageContext:
    """Handed to a stage body so it can record outputs and check lessons."""

    def __init__(self, project: Project, stage: str, run_id: int):
        self.project = project
        self.stage = stage
        self.run_id = run_id
        self.outputs: dict[str, Any] = {}

    def record(self, **kw: Any) -> None:
        self.outputs.update(kw)


def stage(
    name: str,
    inputs: Callable[..., Any] | None = None,
) -> Callable:
    """Decorate a stage function.

    The wrapped function is called as fn(project, ctx, **kwargs). `inputs` is an
    optional callable (project, **kwargs) -> hashable describing what the stage
    depends on; when it matches a prior successful run the stage is skipped.
    """

    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(project: Project, *args: Any, force: bool = False, **kwargs: Any) -> Any:
            from .hashing import stable_hash

            inputs_hash = ""
            if inputs is not None:
                try:
                    inputs_hash = stable_hash(inputs(project, **kwargs))
                except Exception:  # an unhashable input just means "always run"
                    inputs_hash = ""

            if inputs_hash and not force:
                prior = project.db.one(
                    "SELECT * FROM run WHERE stage=? AND inputs_hash=? AND ok=1 "
                    "ORDER BY id DESC LIMIT 1",
                    (name, inputs_hash),
                )
                if prior:
                    return StageSkipped(
                        stage=name,
                        inputs_hash=inputs_hash,
                        previous=json.loads(prior.get("outputs_json") or "{}"),
                    )

            cur = project.db.execute(
                "INSERT INTO run (stage, args_json, inputs_hash, started, ok) VALUES (?,?,?,?,0)",
                (name, json.dumps(kwargs, default=str), inputs_hash, now_iso()),
            )
            run_id = int(cur.lastrowid)
            ctx = StageContext(project, name, run_id)
            started = time.time()
            try:
                result = fn(project, ctx, *args, **kwargs)
            except Exception as exc:
                project.db.execute(
                    "UPDATE run SET ended=?, ok=0, outputs_json=? WHERE id=?",
                    (now_iso(), json.dumps({"error": str(exc)}), run_id),
                )
                raise
            ctx.outputs.setdefault("duration_s", round(time.time() - started, 2))
            project.db.execute(
                "UPDATE run SET ended=?, ok=1, outputs_json=? WHERE id=?",
                (now_iso(), json.dumps(ctx.outputs, default=str), run_id),
            )
            return result

        wrapper.stage_name = name  # type: ignore[attr-defined]
        return wrapper

    return decorator
