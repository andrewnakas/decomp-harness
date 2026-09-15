from __future__ import annotations

import pytest

from decomp.pipeline.loop import run as run_loop


@pytest.fixture
def loopable(project, fixtures, tmp_path):
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


def test_a_round_drafts_what_it_can_and_reports_the_cost(loopable):
    result = run_loop(loopable, n=4, no_session=True)
    assert result.rounds
    first = result.rounds[0]
    assert first.picked > 0
    assert first.drafted >= 1          # the fixture's load-and-store function
    assert first.tokens == 0           # a mechanical round spends nothing
    assert "per written port" in first.brief()


def test_an_unconfigured_stage_stops_cleanly(loopable):
    """A stage that is not set up yet should say what to set, and leave the
    written ports in place for when it is."""
    result = run_loop(loopable, n=4)
    first = result.rounds[0]
    assert first.stopped_at == "build"
    assert "build.artifact" in first.why
    assert loopable.db.scalar("SELECT COUNT(*) FROM port") > 0


def test_an_empty_queue_stops_the_loop(project):
    result = run_loop(project, n=4)
    assert result.rounds[0].stopped_at == "queue"
    assert "nothing open" in result.rounds[0].why


def test_a_round_that_writes_nothing_does_not_try_to_build(loopable):
    """There is nothing to build, so a build failure here would be noise."""
    # Leave only functions the drafter refuses and the provider cannot answer.
    loopable.db.execute(
        "UPDATE function SET in_corpus=0 WHERE addr NOT IN (0x82B10000)"
    )
    result = run_loop(loopable, n=4)
    first = result.rounds[0]
    assert first.stopped_at == "port"
    assert "nothing was written" in first.why


def test_a_cost_ceiling_stops_the_loop(loopable, tmp_path, monkeypatch):
    from decomp.pipeline import loop as loop_mod
    from decomp.pipeline.port import PortOutcome, PortRunResult

    def expensive(project, addrs, **kw):
        return PortRunResult(outcomes=[
            PortOutcome(addr=a, ok=True, status="written", tokens=1000,
                        cost_usd=5.0, model="pretend")
            for a in addrs
        ])

    monkeypatch.setattr(loop_mod, "port_stage", None, raising=False)
    import decomp.pipeline.port as port_module

    monkeypatch.setattr(port_module, "port_many", expensive)
    result = run_loop(loopable, n=2, max_cost_usd=1.0)
    first = result.rounds[0]
    assert first.stopped_at == "budget"
    assert "$1.00" in first.why


def test_multiple_rounds_accumulate(loopable):
    result = run_loop(loopable, n=1, rounds=3, no_session=True)
    assert len(result.rounds) >= 1
    assert result.tokens == sum(r.tokens for r in result.rounds)
