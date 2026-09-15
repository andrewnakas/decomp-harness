"""`decomp screen`: decide, statically and for free, what can be verified.

This is the cheapest stage with the largest effect. The audio project's corpus
was 1,694 functions; screening plus thread attribution reduced the pool that was
worth any model's attention to a few hundred. Nothing here costs a token.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..core.stages import now_iso, stage

if TYPE_CHECKING:
    from ..core.config import Project


@dataclass
class ScreenResult:
    screened: int
    gates: dict[str, int] = field(default_factory=dict)
    suspects: int = 0
    examples: list[str] = field(default_factory=list)

    @property
    def passing(self) -> int:
        return self.gates.get("pass", 0)

    def brief(self) -> str:
        lines = [
            f"screened\t{self.screened}",
            "gates\t" + " ".join(f"{k}={v}" for k, v in sorted(self.gates.items())),
        ]
        if self.screened:
            share = self.passing / self.screened
            lines.append(f"verifiable\t{self.passing}\t{share:.0%}")
        if self.suspects:
            lines.append(f"deref_windows\t{self.suspects} function(s) need a pre-call read")
        lines.extend(f"  {e}" for e in self.examples[:4])
        return "\n".join(lines)


@stage(
    "screen",
    inputs=lambda p, **kw: [
        kw.get("subsystem"), kw.get("scope"),
        p.db.scalar("SELECT COUNT(*) FROM function WHERE in_corpus=1", (), 0),
        p.db.meta_get("truth.lifted_dir"),
    ],
)
def screen(project: "Project", ctx, subsystem: str = "", scope: str = "corpus",
           limit: int = 0) -> ScreenResult:
    """Screen corpus functions for the four verification gates."""
    from ..adapters.groundtruth.lifted_rexglue import from_project as truth_from_project
    from ..adapters.screen.rexglue_census import from_project as screener_from_project

    gt = truth_from_project(project)
    screener = screener_from_project(project)

    sql = "SELECT addr FROM function WHERE 1=1"
    params: list = []
    if scope == "corpus":
        sql += " AND in_corpus=1"
    if subsystem:
        sql += " AND subsystem_id=(SELECT id FROM subsystem WHERE name=?)"
        params.append(subsystem)
    sql += " ORDER BY COALESCE(hot,0) DESC, addr"
    if limit:
        sql += f" LIMIT {int(limit)}"

    addrs = [r["addr"] for r in project.db.query(sql, tuple(params))]
    gates: dict[str, int] = {}
    suspects = 0
    examples: list[str] = []

    with project.db.tx():
        for addr in addrs:
            result = screener.screen(addr, gt.body(addr))
            gates[result.gate] = gates.get(result.gate, 0) + 1
            n_suspect = result.census.get("gate2_suspects", 0)
            if n_suspect:
                suspects += 1

            project.db.upsert(
                "gate",
                {
                    "addr": addr,
                    "gate": result.gate,
                    "reasons_json": json.dumps(result.reasons),
                    "store_prov_json": json.dumps(
                        [
                            {"line": s.line, "base": s.base, "ref": s.base_ref,
                             "offset": s.offset, "size": s.size}
                            for s in result.stores
                        ]
                    ),
                    "windows_json": json.dumps(result.suggested_windows),
                    "rules_version": screener.rules_version,
                    "screened_at": now_iso(),
                },
                "addr",
            )
            project.db.upsert(
                "function",
                {
                    "addr": addr,
                    "gate": None if result.passes else result.gate,
                    "gate_reason": "; ".join(result.reasons)[:200] or None,
                    "gate2_suspects": n_suspect,
                    "updated_at": now_iso(),
                },
                "addr",
            )
            if not result.passes and len(examples) < 4:
                examples.append(result.brief())

    ctx.record(screened=len(addrs), gates=gates)
    return ScreenResult(
        screened=len(addrs), gates=gates, suspects=suspects, examples=examples
    )
