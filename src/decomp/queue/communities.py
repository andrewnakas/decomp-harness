"""Finding subsystems in a call graph, without being told where they are.

A binary has natural seams: the audio engine calls into itself far more than it
calls the renderer. Label propagation finds those seams cheaply, which matters
because the alternative is a person guessing an address range, and the audio
project's own notes call that approach leaky.

Pure Python and O(edges) per round, so 47,000 functions and 209,000 edges take
seconds rather than needing a graph library.
"""

from __future__ import annotations

import random
from collections import Counter, defaultdict
from dataclasses import dataclass, field


@dataclass
class Community:
    id: int
    members: set[int] = field(default_factory=set)
    internal_edges: int = 0
    external_edges: int = 0

    @property
    def size(self) -> int:
        return len(self.members)

    @property
    def cohesion(self) -> float:
        """Share of this community's edges that stay inside it.

        A cohesive community is one whose functions mostly talk to each other,
        which is what makes it a subsystem rather than an arbitrary cut.
        """
        total = self.internal_edges + self.external_edges
        return self.internal_edges / total if total else 0.0


def propagate(edges: list[tuple[int, int]], rounds: int = 12,
              seed: int = 0, min_size: int = 2) -> dict[int, int]:
    """Assign each node a community label. Returns node -> label.

    Every node starts as its own community and repeatedly adopts whichever label
    is most common among its neighbours. Ties break toward the lowest label so
    the result is the same on every run: an unstable partition would make the
    subsystem list reshuffle between invocations for no reason.
    """
    neighbours: dict[int, list[int]] = defaultdict(list)
    for caller, callee in edges:
        if caller == callee:
            continue
        neighbours[caller].append(callee)
        neighbours[callee].append(caller)

    if not neighbours:
        return {}

    labels = {node: node for node in neighbours}
    order = sorted(neighbours)
    rng = random.Random(seed)

    for _ in range(rounds):
        rng.shuffle(order)
        changed = 0
        for node in order:
            counts = Counter(labels[n] for n in neighbours[node])
            if not counts:
                continue
            best = max(counts.values())
            # Deterministic tie-break keeps the partition reproducible.
            winner = min(label for label, n in counts.items() if n == best)
            if winner != labels[node]:
                labels[node] = winner
                changed += 1
        if not changed:
            break

    sizes = Counter(labels.values())
    return {node: label for node, label in labels.items() if sizes[label] >= min_size}


def summarize(labels: dict[int, int], edges: list[tuple[int, int]]) -> list[Community]:
    """Group nodes into communities and measure how self-contained each is.

    Communities are renumbered from 1 in descending size order. The raw labels
    are node addresses, and asking a person to type `pick 2192028880` is a worse
    interface than `pick 1` for no gain.
    """
    grouped: dict[int, Community] = {}
    for node, label in labels.items():
        grouped.setdefault(label, Community(id=label)).members.add(node)

    for caller, callee in edges:
        a, b = labels.get(caller), labels.get(callee)
        if a is None and b is None:
            continue
        if a == b and a is not None:
            grouped[a].internal_edges += 1
        else:
            if a is not None:
                grouped[a].external_edges += 1
            if b is not None:
                grouped[b].external_edges += 1

    ordered = sorted(grouped.values(), key=lambda c: (-c.size, min(c.members)))
    for index, community in enumerate(ordered, start=1):
        community.id = index
    return ordered
