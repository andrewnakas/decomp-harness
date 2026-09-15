from __future__ import annotations

from decomp.core.stages import StageSkipped, stage


def test_stage_skips_when_inputs_unchanged(project):
    calls = []

    @stage("demo", inputs=lambda p, **kw: kw.get("value"))
    def demo(proj, ctx, value=1):
        calls.append(value)
        ctx.record(value=value)
        return f"ran {value}"

    assert demo(project, value=1) == "ran 1"
    second = demo(project, value=1)
    assert isinstance(second, StageSkipped)
    assert second.previous["value"] == 1
    assert calls == [1]

    # A different input runs again; --force reruns regardless.
    assert demo(project, value=2) == "ran 2"
    assert demo(project, value=1, force=True) == "ran 1"
    assert calls == [1, 2, 1]


def test_failed_stage_is_not_skipped_next_time(project):
    attempts = []

    @stage("flaky", inputs=lambda p, **kw: "fixed")
    def flaky(proj, ctx):
        attempts.append(1)
        raise ValueError("nope")

    for _ in range(2):
        try:
            flaky(project)
        except ValueError:
            pass
    assert len(attempts) == 2  # a failure never records a reusable success

    row = project.db.one("SELECT * FROM run WHERE stage='flaky' ORDER BY id DESC LIMIT 1")
    assert row["ok"] == 0
