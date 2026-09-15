"""`decomp promote`: decide which verified ports are allowed to run for real.

Verified says a comparison never disagreed. Promoted says the comparison covered
enough of the function to mean something. The audio project's rule, kept here
because the reasoning holds: at least one comparable call per line of body, and
at least a hundred calls, measured on the weaker of the profiles a function was
seen in. A flat threshold would hold a small function to the same bar as a large
one, which is either too strict or too loose depending on its size.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..core.db import addr_str
from ..core.stages import now_iso

if TYPE_CHECKING:
    from ..core.config import Project


@dataclass
class PromotionDecision:
    addr: int
    promoted: bool
    calls: int
    lines: int
    ratio: float
    reason: str = ""

    def brief(self) -> str:
        verb = "promoted" if self.promoted else "held"
        return (
            f"{addr_str(self.addr)}\t{verb}\tcalls={self.calls}\tlines={self.lines}"
            f"\tcalls/line={self.ratio:.1f}\t{self.reason}"
        )


@dataclass
class PromoteResult:
    decisions: list[PromotionDecision] = field(default_factory=list)
    skipped_untrusted: int = 0

    @property
    def promoted(self) -> int:
        return sum(1 for d in self.decisions if d.promoted)

    @property
    def held(self) -> int:
        return sum(1 for d in self.decisions if not d.promoted)

    def brief(self) -> str:
        lines = [d.brief() for d in self.decisions[:20]]
        if len(self.decisions) > 20:
            lines.append(f"... and {len(self.decisions) - 20} more")
        lines.append(f"--\tpromoted={self.promoted}\theld={self.held}")
        if self.skipped_untrusted:
            lines.append(
                f"skipped\t{self.skipped_untrusted} verdict(s) from untrusted sessions"
            )
        return "\n".join(lines)


def run(project: Project, min_calls: int = 0, min_ratio: float = 0.0,
        dry_run: bool = False) -> PromoteResult:
    min_calls = min_calls or project.get("oracle.promote_min_calls", 100)
    min_ratio = min_ratio or project.get("oracle.promote_min_calls_per_line", 1.0)

    rows = project.db.query(
        "SELECT f.addr, f.lifted_lines, f.ghidra_lines, f.status "
        "FROM function f WHERE f.status='verified'"
    )
    decisions: list[PromotionDecision] = []
    skipped = 0

    for row in rows:
        addr = row["addr"]
        # The weaker profile decides. A function comfortably exercised in one
        # session and barely touched in another has only been shown to work in
        # the first, and promotion means it runs in both.
        per_session = project.db.query(
            "SELECT v.compared FROM verdict v JOIN session s ON s.id=v.session_id "
            "WHERE v.addr=? AND v.result='verified' AND s.trusted=1",
            (addr,),
        )
        if not per_session:
            skipped += 1
            continue

        calls = min(r["compared"] or 0 for r in per_session)
        lines = row.get("lifted_lines") or row.get("ghidra_lines") or 1
        ratio = calls / max(1, lines)

        if calls < min_calls:
            decisions.append(PromotionDecision(
                addr, False, calls, lines, ratio,
                f"fewer than {min_calls} comparable calls",
            ))
        elif ratio < min_ratio:
            decisions.append(PromotionDecision(
                addr, False, calls, lines, ratio,
                f"under {min_ratio} call per line: thinly covered for its size",
            ))
        else:
            decisions.append(PromotionDecision(addr, True, calls, lines, ratio,
                                               "evidence is sufficient"))

    if not dry_run:
        with project.db.tx():
            for d in decisions:
                status = "promoted" if d.promoted else "thin"
                project.db.upsert(
                    "function", {"addr": d.addr, "status": status,
                                 "updated_at": now_iso()}, "addr",
                )
                project.db.execute(
                    "UPDATE port SET status=? WHERE addr=?", (status, d.addr)
                )

    return PromoteResult(decisions=decisions, skipped_untrusted=skipped)
