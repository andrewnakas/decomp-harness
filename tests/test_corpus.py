from __future__ import annotations

import json

import pytest

from decomp.pipeline.corpus import CallGraph, grow, load_callgraph, resolve_seeds
from decomp.pipeline.importer import import_lifted


@pytest.fixture
def graphed(project, fixtures):
    """A project whose call graph is a small known shape.

        seed -> a -> b -> c        (guest chain)
        seed -> imp                (import, stops)
        seed -> helper             (helper, stops)
        a    -> 0                  (indirect, stops)
    """
    edges = [
        (0x1000, 0x2000, "direct"),
        (0x2000, 0x3000, "direct"),
        (0x3000, 0x4000, "direct"),
        (0x1000, 0x9000, "import"),
        (0x1000, 0x9100, "helper"),
        (0x2000, 0, "indirect"),
    ]
    for caller, callee, kind in edges:
        project.db.upsert(
            "xref",
            {"caller": caller, "callee": callee, "callee_name": f"s{callee:x}",
             "kind": kind, "site_line": 0},
            ("caller", "callee", "callee_name", "site_line"),
        )
    for addr in (0x1000, 0x2000, 0x3000, 0x4000):
        project.db.upsert("function", {"addr": addr}, "addr")
    project.db.upsert("function", {"addr": 0x9000, "is_import": 1}, "addr")
    project.db.upsert("function", {"addr": 0x9100, "is_helper": 1}, "addr")
    return project


def test_closure_follows_guest_calls_and_stops_at_the_runtime(graphed):
    res = grow(graphed, seeds=["1000"], subsystem="demo")
    assert res.size == 4                       # seed plus the three-deep chain
    assert res.depth_histogram == {0: 1, 1: 1, 2: 1, 3: 1}
    assert res.stopped["import"] == 1
    assert res.stopped["helper"] == 1
    assert res.stopped["indirect"] == 1

    in_corpus = {
        r["addr"] for r in graphed.db.query("SELECT addr FROM function WHERE in_corpus=1")
    }
    assert in_corpus == {0x1000, 0x2000, 0x3000, 0x4000}
    assert graphed.db.scalar("SELECT seed FROM function WHERE addr=?", (0x1000,)) == 1
    assert graphed.db.scalar("SELECT seed FROM function WHERE addr=?", (0x2000,)) == 0


def test_max_depth_bounds_the_walk_and_reports_the_frontier(graphed):
    res = grow(graphed, seeds=["1000"], max_depth=2, subsystem="demo")
    assert res.size == 3
    assert 0x4000 not in {
        r["addr"] for r in graphed.db.query("SELECT addr FROM function WHERE in_corpus=1")
    }
    assert any(addr == 0x3000 for addr, _ in res.frontier)


def test_following_helpers_is_opt_in(graphed):
    res = grow(graphed, seeds=["1000"], stop_kinds=(), subsystem="demo", force=True)
    # Imports and helpers are still excluded by their function flags, which is
    # the durable signal; the kind filter is only the first line of defence.
    assert 0x9000 not in {
        r["addr"] for r in graphed.db.query("SELECT addr FROM function WHERE in_corpus=1")
    }
    assert res.stopped.get("runtime", 0) == 2


def test_growing_a_second_subsystem_leaves_the_first_alone(graphed):
    grow(graphed, seeds=["1000"], subsystem="first")
    graphed.db.upsert("function", {"addr": 0x5000}, "addr")
    graphed.db.upsert(
        "xref",
        {"caller": 0x5000, "callee": 0x6000, "callee_name": "x", "kind": "direct",
         "site_line": 0},
        ("caller", "callee", "callee_name", "site_line"),
    )
    graphed.db.upsert("function", {"addr": 0x6000}, "addr")
    grow(graphed, seeds=["5000"], subsystem="second")

    still_in = graphed.db.scalar("SELECT in_corpus FROM function WHERE addr=?", (0x2000,))
    assert still_in == 1
    names = {r["name"] for r in graphed.db.query("SELECT name FROM subsystem")}
    assert names == {"first", "second"}


def test_seeds_come_from_arguments_file_or_subsystem(graphed, tmp_path):
    assert resolve_seeds(graphed, ["0x1000", "sub_2000", "junk"], None, None) == [
        0x1000, 0x2000
    ]

    f = tmp_path / "seeds.txt"
    f.write_text("1000\n# a comment\n\n2000  # trailing\n")
    assert resolve_seeds(graphed, None, f, None) == [0x1000, 0x2000]

    graphed.db.upsert(
        "subsystem", {"name": "s", "seeds_json": json.dumps([0x3000])}, "name"
    )
    assert resolve_seeds(graphed, None, None, "s") == [0x3000]


def test_growing_without_seeds_is_an_error(graphed):
    with pytest.raises(ValueError, match="no seeds"):
        grow(graphed, seeds=[], subsystem="demo")


def test_callgraph_is_built_from_the_corpus_when_absent(project, fixtures):
    import_lifted(project, path=fixtures / "lifted")
    graph = load_callgraph(project)
    assert 0x82B10100 in graph.callees(0x82B10000)
    assert 0x82B10000 in graph.callers(0x82B10100)
    # Building it also persists the edges for later stages.
    assert project.db.scalar("SELECT COUNT(*) FROM xref") > 0


def test_callgraph_ignores_the_zero_sentinel():
    graph = CallGraph()
    graph.add(1, 0, "indirect")
    assert graph.callees(1) == set()
