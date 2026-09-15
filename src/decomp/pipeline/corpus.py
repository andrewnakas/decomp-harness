"""Corpus: bound the work by call-graph closure, not by an address range.

The audio project started with an address window and found it "leaky", then
switched to closure from seeds. Closure is the honest boundary: a function is in
scope when the work reaches it, and the frontier tells you where scope ends.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from ..core.db import parse_addr
from ..core.stages import now_iso, stage

if TYPE_CHECKING:
    from ..core.config import Project

# Runtime bands that every subsystem reaches and no subsystem owns. Walking into
# them turns any closure into the whole binary.
DEFAULT_STOP_KINDS = ("import", "helper", "indirect")


@dataclass
class CallGraph:
    """In-memory call graph, built once and reused by closure and clustering."""

    out_edges: dict[int, set[int]] = field(default_factory=lambda: defaultdict(set))
    in_edges: dict[int, set[int]] = field(default_factory=lambda: defaultdict(set))
    kinds: dict[tuple[int, int], str] = field(default_factory=dict)

    def add(self, caller: int, callee: int, kind: str) -> None:
        if not callee:
            return
        self.out_edges[caller].add(callee)
        self.in_edges[callee].add(caller)
        self.kinds[(caller, callee)] = kind

    def callees(self, addr: int) -> set[int]:
        return self.out_edges.get(addr, set())

    def callers(self, addr: int) -> set[int]:
        return self.in_edges.get(addr, set())

    @property
    def nodes(self) -> set[int]:
        return set(self.out_edges) | set(self.in_edges)


@dataclass
class CorpusResult:
    seeds: int
    size: int
    depth_histogram: dict[int, int] = field(default_factory=dict)
    frontier: list[tuple[int, str]] = field(default_factory=list)
    stopped: dict[str, int] = field(default_factory=dict)
    subsystem: str = ""

    def brief(self) -> str:
        lines = [
            f"corpus\t{self.subsystem or '(unnamed)'}\tseeds={self.seeds}\tsize={self.size}",
            "depth\t" + " ".join(f"{d}={n}" for d, n in sorted(self.depth_histogram.items())),
        ]
        if self.stopped:
            lines.append("stopped\t" + " ".join(f"{k}={v}" for k, v in self.stopped.items()))
        if self.frontier:
            shown = " ".join(f"sub_{a:08X}" for a, _ in self.frontier[:6])
            lines.append(f"frontier\t{len(self.frontier)}\t{shown}")
        return "\n".join(lines)


def load_callgraph(project: Project, rebuild: bool = False) -> CallGraph:
    """Build the call graph, from the database if populated, else from the corpus."""
    graph = CallGraph()
    rows = project.db.query("SELECT caller, callee, kind FROM xref WHERE callee != 0")
    if rows and not rebuild:
        for r in rows:
            graph.add(r["caller"], r["callee"], r["kind"])
        return graph

    from ..adapters.groundtruth.lifted_rexglue import from_project

    gt = from_project(project)
    with project.db.tx():
        for caller, callee, name, kind, line in gt.walk_callgraph():
            graph.add(caller, callee, kind)
            project.db.upsert(
                "xref",
                {
                    "caller": caller, "callee": callee or 0, "callee_name": name or "",
                    "kind": kind, "site_line": line or 0,
                },
                ("caller", "callee", "callee_name", "site_line"),
            )
    return graph


def resolve_seeds(project: Project, seeds: list[str] | None,
                  seed_file: Path | str | None = None,
                  subsystem: str | None = None) -> list[int]:
    """Seeds may be addresses, a file of addresses, or a named subsystem."""
    addrs: list[int] = []
    for s in seeds or []:
        try:
            addrs.append(parse_addr(s))
        except ValueError:
            continue
    if seed_file:
        for line in Path(seed_file).read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                addrs.append(parse_addr(line))
            except ValueError:
                continue
    if subsystem:
        row = project.db.one("SELECT seeds_json FROM subsystem WHERE name=?", (subsystem,))
        if row and row["seeds_json"]:
            import json

            addrs.extend(int(a) for a in json.loads(row["seeds_json"]))
    seen: set[int] = set()
    return [a for a in addrs if not (a in seen or seen.add(a))]


@stage(
    "corpus.grow",
    inputs=lambda p, **kw: [
        sorted(kw.get("seeds") or []), str(kw.get("seed_file") or ""),
        kw.get("subsystem"), kw.get("max_depth"), kw.get("stop_kinds"),
    ],
)
def grow(project: Project, ctx, seeds: list[str] | None = None,
         seed_file: Path | str | None = None, subsystem: str = "",
         max_depth: int = 0, stop_kinds: tuple[str, ...] = DEFAULT_STOP_KINDS,
         reset: bool = True) -> CorpusResult:
    """Grow the corpus from seeds by following resolved guest calls.

    Imports, compiler helpers and indirect targets stop the walk: they belong to
    the runtime, not to the subsystem, and following them swallows the binary.
    """
    seed_addrs = resolve_seeds(project, seeds, seed_file, subsystem or None)
    if not seed_addrs:
        raise ValueError("no seeds: pass addresses, --seed-file, or --subsystem")

    graph = load_callgraph(project)
    known = {
        r["addr"]: r
        for r in project.db.query("SELECT addr, is_import, is_helper FROM function")
    }

    depth: dict[int, int] = {a: 0 for a in seed_addrs}
    queue = deque(seed_addrs)
    stopped: dict[str, int] = defaultdict(int)
    frontier: list[tuple[int, str]] = []

    while queue:
        addr = queue.popleft()
        d = depth[addr]
        if max_depth and d >= max_depth:
            frontier.append((addr, "max-depth"))
            continue
        for callee in graph.callees(addr):
            kind = graph.kinds.get((addr, callee), "direct")
            if kind in stop_kinds:
                stopped[kind] += 1
                continue
            row = known.get(callee)
            if row and (row["is_import"] or row["is_helper"]):
                stopped["runtime"] += 1
                continue
            if callee in depth:
                continue
            depth[callee] = d + 1
            queue.append(callee)

    # Indirect edges carry no target, so the walk never sees them; but how many
    # a corpus contains is exactly what gate screening will care about, so count
    # them from the edge table rather than leaving them unreported.
    if depth:
        placeholders = ",".join("?" for _ in depth)
        indirect = project.db.scalar(
            f"SELECT COUNT(*) FROM xref WHERE kind='indirect' AND caller IN ({placeholders})",
            tuple(depth),
            0,
        )
        if indirect:
            stopped["indirect"] = indirect

    subsystem_id = None
    if subsystem:
        project.db.upsert(
            "subsystem",
            {"name": subsystem, "size": len(depth), "seeds_json": _json(seed_addrs)},
            "name",
        )
        subsystem_id = project.db.scalar(
            "SELECT id FROM subsystem WHERE name=?", (subsystem,)
        )

    with project.db.tx():
        if reset and subsystem_id is not None:
            project.db.execute(
                "UPDATE function SET in_corpus=0, corpus_depth=NULL WHERE subsystem_id=?",
                (subsystem_id,),
            )
        elif reset:
            project.db.execute("UPDATE function SET in_corpus=0, corpus_depth=NULL")
        for addr, d in depth.items():
            project.db.upsert(
                "function",
                {
                    "addr": addr, "in_corpus": 1, "corpus_depth": d,
                    "subsystem_id": subsystem_id, "seed": 1 if d == 0 else 0,
                    "updated_at": now_iso(),
                },
                "addr",
            )

    histogram: dict[int, int] = defaultdict(int)
    for d in depth.values():
        histogram[d] += 1

    ctx.record(size=len(depth), seeds=len(seed_addrs))
    return CorpusResult(
        seeds=len(seed_addrs),
        size=len(depth),
        depth_histogram=dict(histogram),
        frontier=frontier,
        stopped=dict(stopped),
        subsystem=subsystem,
    )


def _json(obj) -> str:
    import json

    return json.dumps(obj)
