from __future__ import annotations

import pytest

from decomp.pipeline.auto import run as run_auto
from decomp.pipeline.loop import RoundResult


@pytest.fixture
def workable(project, fixtures, tmp_path):
    from decomp.pipeline.importer import import_lifted, import_xrefs
    from decomp.pipeline.queue import build as queue_build
    from decomp.pipeline.screen import screen

    import_lifted(project, path=fixtures / "lifted")
    project.db.execute("UPDATE function SET in_corpus=1 WHERE addr < 0x82F00000")
    import_xrefs(project, scope="corpus")
    screen(project)
    queue_build(project)
    project.config["providers"]["default"] = "replay"
    project.config["providers"]["replay"] = {"dir": str(tmp_path / "cassettes")}
    return project


def _rounds(monkeypatch, *results):
    """Feed the runner a scripted sequence of rounds."""
    from decomp.pipeline import auto as auto_mod
    from decomp.pipeline.loop import LoopResult

    sequence = list(results)

    def fake_loop(project, **kw):
        if not sequence:
            return LoopResult(rounds=[RoundResult(round=0, picked=0,
                                                  stopped_at="queue",
                                                  why="nothing open to work on")])
        return LoopResult(rounds=[sequence.pop(0)])

    monkeypatch.setattr(auto_mod, "loop_mod", None, raising=False)
    import decomp.pipeline.loop as loop_module

    monkeypatch.setattr(loop_module, "run", fake_loop)


def test_it_stops_when_the_queue_empties(workable):
    result = run_auto(workable, batch=2, max_cost_usd=1.0, max_rounds=20)
    assert "nothing left" in result.stopped_because or result.written > 0
    assert result.remaining == 0 or result.written > 0


def test_repeated_failure_stops_the_run(workable, monkeypatch):
    """A provider that is not signed in fails every round the same way, and a
    loop without a circuit breaker pays for all of them."""
    _rounds(
        monkeypatch,
        RoundResult(round=1, picked=8, failed=8, tokens=5000, cost_usd=0.10),
        RoundResult(round=2, picked=8, failed=8, tokens=5000, cost_usd=0.10),
        RoundResult(round=3, picked=8, failed=8, tokens=5000, cost_usd=0.10),
    )
    result = run_auto(workable, batch=8, max_cost_usd=100.0)
    assert "rounds in a row produced nothing usable" in result.stopped_because
    assert len(result.rounds) == 2          # stopped before the third
    assert result.cost == pytest.approx(0.20)


def test_a_round_that_blocks_functions_is_not_a_failure(workable, monkeypatch):
    """Marking work unverifiable is a result, not a broken setup."""
    _rounds(
        monkeypatch,
        RoundResult(round=1, picked=8, blocked=8, tokens=4000, cost_usd=0.05),
        RoundResult(round=2, picked=8, blocked=8, tokens=4000, cost_usd=0.05),
        RoundResult(round=3, picked=8, drafted=8),
    )
    result = run_auto(workable, batch=8, max_cost_usd=100.0, max_rounds=3)
    assert "produced nothing usable" not in result.stopped_because
    assert result.blocked == 16


def test_the_spend_ceiling_stops_it(workable, monkeypatch):
    _rounds(
        monkeypatch,
        RoundResult(round=1, picked=8, ported=8, tokens=9000, cost_usd=0.60),
        RoundResult(round=2, picked=8, ported=8, tokens=9000, cost_usd=0.60),
        RoundResult(round=3, picked=8, ported=8, tokens=9000, cost_usd=0.60),
    )
    result = run_auto(workable, batch=8, max_cost_usd=1.0)
    assert "ceiling" in result.stopped_because
    assert result.cost <= 1.5          # stops at the first round that crosses


def test_a_refusing_stage_stops_it(workable, monkeypatch):
    """A build host that is unreachable will not become reachable by retrying."""
    _rounds(
        monkeypatch,
        RoundResult(round=1, picked=8, ported=8, stopped_at="build",
                    why="set build.artifact in decomp.toml"),
    )
    result = run_auto(workable, batch=8, max_cost_usd=10.0)
    assert "build refused" in result.stopped_because
    assert "build.artifact" in result.stopped_because


def test_a_round_limit_stops_it(workable, monkeypatch):
    _rounds(
        monkeypatch,
        *[RoundResult(round=i, picked=2, drafted=2) for i in range(1, 6)],
    )
    result = run_auto(workable, batch=2, max_rounds=3, max_cost_usd=100.0)
    assert result.stopped_because == "completed 3 rounds"
    assert len(result.rounds) == 3


def test_the_summary_says_the_ports_are_unverified(workable):
    """Writing a port and proving it are different claims."""
    result = run_auto(workable, batch=2, max_rounds=1, max_cost_usd=1.0)
    assert "not verified" in result.brief()
    assert "build host" in result.brief()


def test_progress_is_reported_against_where_it_started(workable, monkeypatch):
    _rounds(monkeypatch, RoundResult(round=1, picked=2, drafted=2))
    result = run_auto(workable, batch=2, max_rounds=1, max_cost_usd=10.0)
    assert result.started_pending > 0
    assert "progress" in result.brief()
