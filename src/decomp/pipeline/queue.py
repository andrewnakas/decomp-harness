"""`decomp queue`: what to work on next, and why.

The queue is the harness's memory of intent. It survives a killed session, it
records why a function was skipped, and it orders work so that the cheapest
wins land first and siblings arrive together.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..core.db import addr_str
from ..core.stages import now_iso, stage
from ..queue import difficulty as difficulty_mod
from ..queue import families as families_mod
from ..queue import tiers as tiers_mod

if TYPE_CHECKING:
    from ..core.config import Project

# Statuses that mean "do not hand this to a model again".
SETTLED = ("verified", "promoted", "thin", "partial", "needs_human",
           "gate1", "gate2", "gate3", "gate4")
OPEN = ("pending", "drafted", "written", "armed", "divergent", "uncalled")


@dataclass
class QueueBuildResult:
    functions: int
    tiers: dict[str, int] = field(default_factory=dict)
    families: int = 0
    largest_family: int = 0
    difficulty_bands: dict[str, int] = field(default_factory=dict)
    have_profiles: bool = True

    def brief(self) -> str:
        lines = [
            f"queued\t{self.functions}",
            "tiers\t" + " ".join(
                f"{t}({tiers_mod.TIER_LABELS.get(t, t)})={n}"
                for t, n in sorted(self.tiers.items(), key=lambda kv: tiers_mod.sort_key(kv[0]))
            ),
            "difficulty\t" + " ".join(f"{k}={v}" for k, v in self.difficulty_bands.items()),
        ]
        if self.families:
            lines.append(f"families\t{self.families}\tlargest={self.largest_family}")
        if not self.have_profiles:
            lines.append(
                "note\tno execution trace imported: hotness is unknown, so ordering "
                "falls back to difficulty. Run `decomp import trace`."
            )
        return "\n".join(lines)


@dataclass
class QueueItem:
    addr: int
    tier: str
    status: str
    difficulty: float
    hot: int
    lines: int
    family: int | None
    vmx: bool
    name: str = ""
    model_tier: str = ""
    batchable: bool = False

    def row(self) -> tuple:
        return (
            addr_str(self.addr), self.tier, self.status, f"{self.difficulty:.2f}",
            self.hot, self.lines, self.family or "", "vmx" if self.vmx else "",
            self.model_tier, "batch" if self.batchable else "", self.name,
        )


@dataclass
class QueueListResult:
    items: list[QueueItem]
    total_open: int = 0

    def brief(self) -> str:
        from ..core.out import table

        if not self.items:
            return "queue\tempty"
        header = ("addr", "tier", "status", "diff", "hot", "lines", "fam",
                  "vec", "model", "batch", "name")
        return table([i.row() for i in self.items], header) + \
            f"\n{len(self.items)} of {self.total_open} open"


# ------------------------------------------------------------------- build
@stage(
    "queue.build",
    inputs=lambda p, **kw: [
        kw.get("subsystem"),
        p.db.scalar("SELECT COUNT(*) FROM gate", (), 0),
        p.db.scalar("SELECT COUNT(*) FROM function WHERE in_corpus=1", (), 0),
        kw.get("cluster"),
    ],
)
def build(project: "Project", ctx, subsystem: str = "", cluster: bool = True) -> QueueBuildResult:
    """Assign tiers, difficulty and families across the corpus."""
    from ..adapters.groundtruth.lifted_rexglue import from_project as truth_from_project

    where = "WHERE in_corpus=1"
    params: list = []
    if subsystem:
        where += " AND subsystem_id=(SELECT id FROM subsystem WHERE name=?)"
        params.append(subsystem)

    rows = project.db.query(
        f"SELECT f.*, g.gate AS screened_gate, g.reasons_json, g.store_prov_json "
        f"FROM function f LEFT JOIN gate g ON g.addr=f.addr {where}",
        tuple(params),
    )
    if not rows:
        raise ValueError("nothing in the corpus: run `decomp corpus grow` first")

    callee_counts = {
        r["caller"]: r["n"]
        for r in project.db.query(
            "SELECT caller, COUNT(*) AS n FROM xref WHERE kind='direct' GROUP BY caller"
        )
    }

    gt = None
    bodies: dict[int, str] = {}
    if cluster:
        gt = truth_from_project(project)
        bodies = {r["addr"]: gt.body(r["addr"]) for r in rows}
    family_map = families_mod.cluster(bodies) if bodies else {}

    # "Never ran" is only meaningful once some session has been observed.
    have_profiles = bool(project.db.scalar("SELECT COUNT(*) FROM trace_call", (), 0))

    tier_counts: dict[str, int] = {}
    bands = {"easy": 0, "medium": 0, "hard": 0}

    with project.db.tx():
        for row in rows:
            addr = row["addr"]
            census = _census_for(row)
            row["callee_count"] = callee_counts.get(addr, 0)
            row["is_leaf"] = 1 if not row["callee_count"] else 0
            row["gate"] = row.get("screened_gate") if row.get("screened_gate") != "pass" else None

            tier = tiers_mod.assign(row, have_profiles=have_profiles)
            score = difficulty_mod.score(row, census)
            tier_counts[tier] = tier_counts.get(tier, 0) + 1
            bands["easy" if score < 0.35 else "medium" if score < 0.70 else "hard"] += 1

            project.db.upsert(
                "function",
                {
                    "addr": addr,
                    "tier": tier,
                    "difficulty": score,
                    "is_leaf": row["is_leaf"],
                    "family_id": family_map.get(addr),
                    "status": row.get("status") or "pending",
                    "updated_at": now_iso(),
                },
                "addr",
            )

    family_sizes = families_mod.summarize(family_map) if family_map else []
    ctx.record(functions=len(rows), families=len(family_sizes),
               have_profiles=have_profiles)
    return QueueBuildResult(
        have_profiles=have_profiles,
        functions=len(rows),
        tiers=tier_counts,
        families=len(family_sizes),
        largest_family=family_sizes[0].size if family_sizes else 0,
        difficulty_bands=bands,
    )


def _census_for(row: dict[str, Any]) -> dict[str, Any]:
    stores = row.get("store_prov_json")
    if not stores:
        return {}
    try:
        parsed = json.loads(stores)
    except (json.JSONDecodeError, TypeError):
        return {}
    return {
        "stores": len(parsed),
        "loops": sum(1 for s in parsed if s.get("base") == "loop"),
        "lines": row.get("lifted_lines") or 0,
    }


# -------------------------------------------------------------------- next
def next_items(project: "Project", tier: str = "", limit: int = 16,
               subsystem: str = "", status: str = "", include_gated: bool = False,
               family_first: bool = True) -> QueueListResult:
    """The next functions worth a model's attention.

    Ordering: tier, then family (so siblings arrive together), then hotness. A
    hot function proves more per session, because a verdict needs calls.
    """
    sql = [
        "SELECT f.* FROM function f WHERE f.in_corpus=1",
    ]
    params: list = []
    if subsystem:
        sql.append("AND f.subsystem_id=(SELECT id FROM subsystem WHERE name=?)")
        params.append(subsystem)
    if tier:
        sql.append("AND f.tier=?")
        params.append(tier)
    if status:
        sql.append("AND f.status=?")
        params.append(status)
    else:
        placeholders = ",".join("?" for _ in OPEN)
        sql.append(f"AND COALESCE(f.status,'pending') IN ({placeholders})")
        params.extend(OPEN)
    if not include_gated:
        sql.append("AND f.gate IS NULL")

    rows = project.db.query(" ".join(sql), tuple(params))
    total_open = len(rows)

    def key(r: dict) -> tuple:
        return (
            tiers_mod.sort_key(r.get("tier") or ""),
            -(r.get("hot") or 0) if not family_first else 0,
            r.get("family_id") or 0,
            -(r.get("hot") or 0),
            r.get("difficulty") or 0.0,
            r["addr"],
        )

    rows.sort(key=key)
    items = []
    for r in rows[: limit or None]:
        score = r.get("difficulty") or 0.0
        items.append(
            QueueItem(
                addr=r["addr"],
                tier=r.get("tier") or "?",
                status=r.get("status") or "pending",
                difficulty=score,
                hot=r.get("hot") or 0,
                lines=r.get("lifted_lines") or 0,
                family=r.get("family_id"),
                vmx=bool(r.get("vmx128")),
                name=r.get("name") or "",
                model_tier=difficulty_mod.tier_for(
                    score, bool(r.get("vmx128")), r.get("attempts") or 0
                ),
                batchable=difficulty_mod.batchable(r, score),
            )
        )
    return QueueListResult(items=items, total_open=total_open)


# ------------------------------------------------------------------ report
@dataclass
class QueueReport:
    by_tier_status: list[tuple[str, str, int]]
    totals: dict[str, int]

    def brief(self) -> str:
        from ..core.out import table

        rows = [
            (t, tiers_mod.TIER_LABELS.get(t, t), s, n)
            for t, s, n in self.by_tier_status
        ]
        body = table(rows, ("tier", "kind", "status", "n"))
        tail = "\t".join(f"{k}={v}" for k, v in self.totals.items())
        return f"{body}\n{tail}"


def report(project: "Project", subsystem: str = "") -> QueueReport:
    where = "WHERE in_corpus=1"
    params: list = []
    if subsystem:
        where += " AND subsystem_id=(SELECT id FROM subsystem WHERE name=?)"
        params.append(subsystem)
    rows = project.db.query(
        f"SELECT tier, COALESCE(status,'pending') AS status, COUNT(*) AS n "
        f"FROM function {where} GROUP BY tier, status",
        tuple(params),
    )
    rows.sort(key=lambda r: (tiers_mod.sort_key(r["tier"] or ""), r["status"]))

    settled = sum(r["n"] for r in rows if r["status"] in SETTLED)
    total = sum(r["n"] for r in rows)
    return QueueReport(
        by_tier_status=[(r["tier"] or "?", r["status"], r["n"]) for r in rows],
        totals={"total": total, "settled": settled, "open": total - settled},
    )


def set_status(project: "Project", addr: int, **fields: Any) -> dict:
    allowed = {
        "status", "tier", "gate", "gate_reason", "note", "attempts",
        "difficulty", "family_id",
    }
    update = {k: v for k, v in fields.items() if k in allowed and v is not None}
    if not update:
        raise ValueError(f"nothing to set; allowed fields: {', '.join(sorted(allowed))}")
    if "status" in update and update["status"] not in (*SETTLED, *OPEN):
        raise ValueError(f"unknown status '{update['status']}'")
    update["addr"] = addr
    update["updated_at"] = now_iso()
    project.db.upsert("function", update, "addr")
    return project.db.one("SELECT * FROM function WHERE addr=?", (addr,)) or {}
