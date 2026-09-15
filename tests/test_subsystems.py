from __future__ import annotations

import pytest

from decomp.queue.communities import propagate, summarize


def _two_clusters() -> list[tuple[int, int]]:
    """Two dense groups joined by a single edge: an obvious seam."""
    left = [(a, b) for a in range(1, 7) for b in range(1, 7) if a < b]
    right = [(a, b) for a in range(20, 26) for b in range(20, 26) if a < b]
    return left + right + [(6, 20)]


def test_dense_groups_separate_at_the_seam():
    labels = propagate(_two_clusters(), seed=1)
    assert labels
    left = {labels[n] for n in range(1, 7)}
    right = {labels[n] for n in range(20, 26)}
    assert len(left) == 1 and len(right) == 1
    assert left != right


def test_communities_are_renumbered_for_humans():
    """Raw labels are node addresses; `pick 2192028880` is a worse interface
    than `pick 1` for no gain."""
    edges = _two_clusters()
    communities = summarize(propagate(edges, seed=1), edges)
    assert [c.id for c in communities] == list(range(1, len(communities) + 1))
    assert communities[0].size >= communities[-1].size


def test_cohesion_measures_how_self_contained_a_group_is():
    edges = _two_clusters()
    communities = summarize(propagate(edges, seed=1), edges)
    # Each cluster has 15 internal edges and shares one bridge.
    assert all(c.cohesion > 0.8 for c in communities)

    star = [(0, n) for n in range(1, 30)]
    loose = summarize(propagate(star, seed=1), star)
    assert not loose or loose[0].cohesion <= 1.0


def test_partition_is_stable_across_runs():
    """An unstable partition would reshuffle the subsystem list between
    invocations for no reason."""
    edges = _two_clusters()
    first = propagate(edges, seed=3)
    second = propagate(edges, seed=3)
    assert first == second


def test_tiny_groups_are_dropped():
    edges = [(1, 2), (3, 4), (5, 6)]
    assert propagate(edges, min_size=3) == {}
    assert propagate(edges, min_size=2)


def test_self_calls_and_empty_graphs_are_handled():
    assert propagate([]) == {}
    assert propagate([(1, 1)]) == {}


# --------------------------------------------------------------------- stage
@pytest.fixture
def graphed(project):
    for caller, callee in _two_clusters():
        project.db.upsert(
            "xref",
            {"caller": caller, "callee": callee, "callee_name": f"s{callee}",
             "kind": "direct", "site_line": 0},
            ("caller", "callee", "callee_name", "site_line"),
        )
    for addr in list(range(1, 7)) + list(range(20, 26)):
        project.db.upsert("function", {"addr": addr}, "addr")
    return project


def test_discovery_ranks_and_stores_candidates(graphed):
    from decomp.pipeline.subsystems import discover

    result = discover(graphed, min_size=3)
    assert result.candidates
    assert result.communities >= 2
    for c in result.candidates:
        assert c.seeds, "a candidate must carry seeds to grow a corpus from"
    stored = graphed.db.query("SELECT name, size FROM subsystem")
    assert stored


def test_discovery_says_what_it_cannot_know(graphed):
    """Hotness and thread attribution were the audio project's sharpest signal;
    their absence should be stated, not silently scored as zero."""
    from decomp.pipeline.subsystems import discover

    result = discover(graphed, min_size=3)
    assert result.no_traces
    assert "no execution trace" in result.brief()
    assert "unscreened" in result.brief()


def test_work_already_claimed_scores_lower(graphed):
    from decomp.pipeline.subsystems import discover

    before = {c.id: c.score for c in discover(graphed, min_size=3).candidates}

    graphed.db.upsert("subsystem", {"name": "done", "size": 6}, "name")
    sub_id = graphed.db.scalar("SELECT id FROM subsystem WHERE name='done'")
    for addr in range(1, 7):
        graphed.db.upsert("function", {"addr": addr, "subsystem_id": sub_id}, "addr")

    after = discover(graphed, min_size=3, force=True)
    claimed = [c for c in after.candidates if c.overlaps]
    assert claimed, "the overlap should be reported"
    for c in claimed:
        assert c.score < before.get(c.id, 1.0)


def test_picking_a_community_grows_its_corpus(graphed):
    from decomp.pipeline.subsystems import discover, pick

    result = discover(graphed, min_size=3)
    chosen = result.candidates[0]
    outcome = pick(graphed, chosen.id, "physics")

    assert outcome["name"] == "physics"
    assert outcome["corpus"] > 0
    assert graphed.db.scalar("SELECT chosen FROM subsystem WHERE name='physics'") == 1
    assert graphed.db.scalar(
        "SELECT COUNT(*) FROM function WHERE in_corpus=1 AND subsystem_id="
        "(SELECT id FROM subsystem WHERE name='physics')"
    ) > 0


def test_picking_an_unknown_community_is_an_error(graphed):
    from decomp.pipeline.subsystems import pick

    with pytest.raises(KeyError, match="not in the ranking"):
        pick(graphed, 9999, "nope")


def test_discovery_without_a_call_graph_is_an_error(project):
    from decomp.pipeline.subsystems import discover

    with pytest.raises(ValueError, match="no call graph"):
        discover(project)
