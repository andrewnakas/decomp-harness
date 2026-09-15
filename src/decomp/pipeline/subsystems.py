"""`decomp subsystems`: find the seams in a binary, and rank what to work on.

Nobody tells the harness where a subsystem is. The audio project began with a
hand-picked address window and found it leaky, then switched to call-graph
closure from seeds. This stage finds the seeds.

Everything it uses is free: the call graph, names already recovered, execution
traces when they exist, and the gate results. No model is involved in deciding
what to work on, because that decision is a measurement, not a judgment.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..core.db import addr_str
from ..core.stages import now_iso, stage
from ..queue.communities import propagate, summarize

if TYPE_CHECKING:
    from ..core.config import Project

# What makes a community worth a person's attention. Weights are deliberately
# blunt: this ranks a shortlist for a human to choose from, it does not decide.
WEIGHTS = {
    "cohesion": 0.30,      # self-contained enough to port without dragging in the world
    "verifiable": 0.30,    # what fraction an oracle could actually bracket
    "hotness": 0.20,       # a verdict needs calls; cold code proves nothing
    "named": 0.10,         # recovered names make the work legible
    "size_fit": 0.10,      # big enough to matter, small enough to finish
}
IDEAL_SIZE = 400


@dataclass
class SubsystemCandidate:
    id: int
    size: int
    cohesion: float
    seeds: list[int] = field(default_factory=list)
    named: int = 0
    hot: int = 0
    verifiable: int = 0
    screened: int = 0
    threads: dict[str, int] = field(default_factory=dict)
    top_names: list[str] = field(default_factory=list)
    overlaps: str = ""
    score: float = 0.0

    @property
    def named_share(self) -> float:
        return self.named / self.size if self.size else 0.0

    @property
    def verifiable_share(self) -> float:
        return self.verifiable / self.screened if self.screened else 0.0

    def row(self) -> tuple:
        thread = max(self.threads, key=self.threads.get) if self.threads else ""
        return (
            self.id, self.size, f"{self.cohesion:.2f}", f"{self.named_share:.0%}",
            f"{self.verifiable_share:.0%}" if self.screened else "-",
            self.hot or "-", thread or "-", self.overlaps or "-",
            f"{self.score:.2f}",
            " ".join(self.top_names[:3]) or " ".join(addr_str(a) for a in self.seeds[:2]),
        )


@dataclass
class SubsystemsResult:
    candidates: list[SubsystemCandidate]
    communities: int = 0
    unscreened: bool = False
    no_traces: bool = False

    def brief(self) -> str:
        from ..core.out import table

        header = ("id", "size", "cohesion", "named", "verifiable", "hot",
                  "thread", "overlaps", "score", "what")
        lines = [table([c.row() for c in self.candidates], header)]
        lines.append(f"--\t{self.communities} communities in the call graph")
        if self.unscreened:
            lines.append(
                "note\tmost of the binary is unscreened, so the verifiable column "
                "is blank. Run `decomp screen --scope all` to fill it in."
            )
        if self.no_traces:
            lines.append(
                "note\tno execution trace imported, so hotness and thread "
                "attribution are unknown. Those were the audio project's sharpest "
                "signal: they cut 1,694 candidates to the 216 that actually run."
            )
        if self.candidates:
            best = self.candidates[0]
            lines.append(
                f"next\tdecomp subsystems pick {best.id} --name <name>"
            )
        return "\n".join(lines)


@stage(
    "subsystems",
    inputs=lambda p, **kw: [
        p.db.scalar("SELECT COUNT(*) FROM xref", (), 0),
        p.db.scalar("SELECT COUNT(*) FROM gate", (), 0),
        kw.get("min_size"), kw.get("max_size"),
    ],
)
def discover(project: Project, ctx, min_size: int = 40, max_size: int = 2500,
             top: int = 12) -> SubsystemsResult:
    """Rank the call graph's communities as candidate subsystems."""
    edges = [
        (r["caller"], r["callee"])
        for r in project.db.query(
            "SELECT caller, callee FROM xref WHERE callee != 0 AND kind='direct'"
        )
    ]
    if not edges:
        raise ValueError(
            "no call graph: run `decomp import lifted` and `decomp corpus grow`, "
            "or `decomp import xrefs --scope all`"
        )

    labels = propagate(edges, min_size=min_size)
    communities = summarize(labels, edges)

    functions = {
        r["addr"]: r
        for r in project.db.query(
            "SELECT addr, name, name_confidence, hot, thread_first, gate, "
            "subsystem_id FROM function"
        )
    }
    gates = {
        r["addr"]: r["gate"]
        for r in project.db.query("SELECT addr, gate FROM gate")
    }
    existing = {
        r["id"]: r["name"]
        for r in project.db.query("SELECT id, name FROM subsystem")
    }

    in_degree: dict[int, int] = {}
    for _, callee in edges:
        in_degree[callee] = in_degree.get(callee, 0) + 1

    candidates: list[SubsystemCandidate] = []
    for community in communities:
        if not (min_size <= community.size <= max_size):
            continue
        candidate = SubsystemCandidate(
            id=community.id, size=community.size, cohesion=community.cohesion
        )
        overlap_counts: dict[str, int] = {}
        for addr in community.members:
            fn = functions.get(addr) or {}
            if fn.get("name") and not str(fn["name"]).startswith("sub_"):
                candidate.named += 1
                if len(candidate.top_names) < 6:
                    candidate.top_names.append(str(fn["name"])[:34])
            candidate.hot = max(candidate.hot, fn.get("hot") or 0)
            thread = fn.get("thread_first")
            if thread:
                candidate.threads[thread] = candidate.threads.get(thread, 0) + 1
            gate = gates.get(addr)
            if gate:
                candidate.screened += 1
                if gate in ("pass", "gate4"):
                    candidate.verifiable += 1
            sub_id = fn.get("subsystem_id")
            if sub_id and sub_id in existing:
                name = existing[sub_id]
                overlap_counts[name] = overlap_counts.get(name, 0) + 1

        if overlap_counts:
            name, count = max(overlap_counts.items(), key=lambda kv: kv[1])
            candidate.overlaps = f"{name}:{count * 100 // candidate.size}%"

        # Seeds are the community's most-called members: closure from them
        # reaches the rest, and they are what a person recognises.
        candidate.seeds = sorted(
            community.members, key=lambda a: -in_degree.get(a, 0)
        )[:12]
        candidate.score = _score(candidate)
        candidates.append(candidate)

    candidates.sort(key=lambda c: -c.score)
    ranked = candidates[:top]

    with project.db.tx():
        for c in ranked:
            project.db.upsert(
                "subsystem",
                {
                    "name": f"community-{c.id}",
                    "seeds_json": json.dumps(c.seeds),
                    "score_json": json.dumps({
                        "score": c.score, "cohesion": c.cohesion,
                        "named": c.named, "verifiable": c.verifiable,
                        "hot": c.hot,
                    }),
                    "size": c.size,
                },
                "name",
            )

    screened_total = project.db.scalar("SELECT COUNT(*) FROM gate", (), 0)
    ctx.record(communities=len(communities), ranked=len(ranked))
    return SubsystemsResult(
        candidates=ranked,
        communities=len(communities),
        unscreened=screened_total < len(functions) // 2,
        no_traces=not project.db.scalar("SELECT COUNT(*) FROM trace_call", (), 0),
    )


def _score(c: SubsystemCandidate) -> float:
    size_fit = 1.0 - min(1.0, abs(c.size - IDEAL_SIZE) / (IDEAL_SIZE * 3))
    hotness = min(1.0, (c.hot or 0) / 100_000) if c.hot else 0.0
    # An unscreened community is not penalised for being unmeasured, but it does
    # not get credit either: it scores the midpoint until someone screens it.
    verifiable = c.verifiable_share if c.screened else 0.5
    total = (
        WEIGHTS["cohesion"] * c.cohesion
        + WEIGHTS["verifiable"] * verifiable
        + WEIGHTS["hotness"] * hotness
        + WEIGHTS["named"] * c.named_share
        + WEIGHTS["size_fit"] * size_fit
    )
    # Work already claimed by another subsystem is not new work.
    if c.overlaps:
        share = int(c.overlaps.split(":")[1].rstrip("%")) / 100
        total *= max(0.1, 1.0 - share)
    return round(total, 3)


def pick(project: Project, community_id: int, name: str,
         max_depth: int = 0) -> dict:
    """Adopt a community as a named subsystem and grow its corpus."""
    from .corpus import grow

    row = project.db.one(
        "SELECT * FROM subsystem WHERE name=?", (f"community-{community_id}",)
    )
    if not row:
        raise KeyError(
            f"community {community_id} is not in the ranking: run "
            f"`decomp subsystems` first"
        )
    seeds = json.loads(row["seeds_json"])
    project.db.upsert(
        "subsystem",
        {"name": name, "seeds_json": row["seeds_json"], "size": row["size"],
         "chosen": 1, "notes": f"adopted from community-{community_id} on {now_iso()}"},
        "name",
    )
    result = grow(project, seeds=[f"{a:08X}" for a in seeds], subsystem=name,
                  max_depth=max_depth, reset=False)
    return {"name": name, "seeds": len(seeds), "corpus": result.size}
