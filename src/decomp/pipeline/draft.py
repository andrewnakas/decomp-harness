"""`decomp draft`: translate mechanically, and report what declined.

Useful on its own as well as inside the port loop: running it over a corpus says
how much of the work needs no model at all, which is worth knowing before
budgeting for one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from ..core.db import addr_str

if TYPE_CHECKING:
    from ..core.config import Project


@dataclass
class DraftResult:
    attempted: int = 0
    drafted: int = 0
    written: list[int] = field(default_factory=list)
    refusals: dict[str, int] = field(default_factory=dict)
    examples: list[str] = field(default_factory=list)

    @property
    def share(self) -> float:
        return self.drafted / self.attempted if self.attempted else 0.0

    def brief(self) -> str:
        lines = [
            f"drafted\t{self.drafted}/{self.attempted}\t{self.share:.0%}"
            f"\tno model called",
        ]
        for reason, count in sorted(self.refusals.items(), key=lambda kv: -kv[1])[:5]:
            lines.append(f"  declined {count:>4}\t{reason}")
        lines.extend(f"  {e}" for e in self.examples[:3])
        if self.written:
            shown = " ".join(addr_str(a) for a in self.written[:6])
            lines.append(f"written\t{shown}")
        return "\n".join(lines)


def _kind_of(reason: str) -> str:
    """Collapse a refusal to its category."""
    if "exceeds the mechanical limit" in reason:
        return "too long for mechanical translation"
    if reason.startswith("unrecognised"):
        return "unrecognised construct"
    return reason.split(":")[0].strip()


def run(project: Project, addrs: list[int] | None = None, subsystem: str = "",
        limit: int = 0, write: bool = True, out_dir: Path | None = None) -> DraftResult:
    """Try a mechanical translation for each function in scope."""
    from ..adapters.draft.lifted_to_native import LiftedToNative
    from ..adapters.groundtruth.lifted_rexglue import from_project as truth_from_project
    from ..pipeline.port import try_draft

    if not addrs:
        sql = "SELECT addr FROM function WHERE in_corpus=1 AND gate IS NULL"
        params: list = []
        if subsystem:
            sql += " AND subsystem_id=(SELECT id FROM subsystem WHERE name=?)"
            params.append(subsystem)
        sql += " AND COALESCE(status,'pending')='pending' ORDER BY COALESCE(hot,0) DESC"
        if limit:
            sql += f" LIMIT {int(limit)}"
        addrs = [r["addr"] for r in project.db.query(sql, tuple(params))]

    gt = truth_from_project(project)
    drafter = LiftedToNative()
    result = DraftResult(attempted=len(addrs))
    target_dir = Path(out_dir) if out_dir else project.sub("ports")

    for addr in addrs:
        fn = project.db.one("SELECT * FROM function WHERE addr=?", (addr,)) or {}
        if write:
            outcome = try_draft(project, addr, fn, target_dir)
            if outcome is not None:
                result.drafted += 1
                result.written.append(addr)
                continue
        attempt = drafter.draft(
            addr, gt.body(addr),
            {"gate": fn.get("gate"), "has_vmx": bool(fn.get("vmx128"))},
        )
        if hasattr(attempt, "code"):
            result.drafted += 1
            continue
        # Group refusals by kind, not by the specific statement or count, so the
        # summary says what the translator is missing rather than listing a
        # thousand near-identical lines.
        reason = _kind_of(attempt.reason)
        result.refusals[reason] = result.refusals.get(reason, 0) + 1
        if reason == "unrecognised construct" and len(result.examples) < 3:
            result.examples.append(attempt.brief())

    return result
