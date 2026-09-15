from __future__ import annotations

import json

from decomp.adapters.provider.base import LLMRequest, LLMResult, Usage
from decomp.core.tokens import DEFAULT_CHARS_PER_TOKEN, ratio_for
from decomp.llm import baseline, ledger


def _result(**kw):
    defaults = dict(
        ok=True, structured={"a": 1}, usage=Usage(100, 4000, 0, 50),
        cost_usd=0.01, session_ref="s1", model="m1", duration_ms=1200,
    )
    defaults.update(kw)
    return LLMResult(**defaults)


def test_record_writes_row_and_calibrates(project):
    req = LLMRequest(prompt="x" * 3000, prefix="brief", purpose="port", addrs=[0x82B28A00])
    before = ratio_for(project)
    assert before == DEFAULT_CHARS_PER_TOKEN

    # 3000 chars billed as 600 fresh input tokens: an observed ratio of 5.0.
    call_id = ledger.record(
        project, "claude", req, _result(usage=Usage(600, 4000, 0, 50)),
        packet_tokens_est=970,
    )
    row = project.db.one("SELECT * FROM llm_call WHERE id=?", (call_id,))
    assert row["provider"] == "claude"
    assert row["cache_read_tokens"] == 4000
    assert row["schema_ok"] == 1
    assert json.loads(row["addrs_json"]) == [0x82B28A00]

    assert before < ratio_for(project) < 5.0   # blended toward the observation


def test_calibration_rejects_implausible_ratios(project):
    """A call dominated by a cached prefix can imply a nonsense ratio; ignore it."""
    req = LLMRequest(prompt="x" * 3000, prefix="brief")
    ledger.record(project, "claude", req, _result(usage=Usage(10, 40000, 0, 5)))
    assert ratio_for(project) == DEFAULT_CHARS_PER_TOKEN


def test_resumed_calls_do_not_skew_calibration(project):
    req = LLMRequest(prompt="y" * 200, prefix="brief", resume_session="s1")
    ledger.record(project, "claude", req, _result(usage=Usage(5000, 0, 0, 10)))
    assert ratio_for(project) == DEFAULT_CHARS_PER_TOKEN


def test_report_totals_and_rates(project):
    req = LLMRequest(prompt="p", prefix="b")
    ledger.record(project, "claude", req, _result(usage=Usage(100, 900, 10, 50)))
    ledger.record(project, "claude", req, _result(usage=Usage(100, 900, 0, 50)))
    project.db.execute(
        "INSERT INTO function (addr, status) VALUES (1,'verified'),(2,'promoted'),(3,'pending')"
    )
    rep = ledger.report(project)
    assert rep.calls == 2
    assert rep.input_tokens == 200
    assert rep.cache_read == 1800
    assert rep.verified == 2          # verified + promoted both count as verified work
    assert rep.promoted == 1
    assert rep.cache_hit_rate == round(1800 / 2000, 3)
    # Per-verified uses the cost-weighted figure, not a raw sum: a raw sum makes
    # a cache-heavy run look far more expensive than it was.
    from decomp.llm.baseline import weighted

    expected = weighted(rep.input_tokens, rep.cache_read, rep.cache_write,
                        rep.output_tokens) / 2
    assert rep.per_verified == round(expected, 1)


def test_report_grouping(project):
    req = LLMRequest(prompt="p")
    ledger.record(project, "claude", req, _result(model="fast"))
    ledger.record(project, "claude", req, _result(model="slow"))
    rep = ledger.report(project, group_by="model")
    assert {r[0] for r in rep.rows} == {"fast", "slow"}
    assert "fast" in rep.brief()


def test_baseline_scans_transcripts(tmp_path):
    projects = tmp_path / "projects"
    real = tmp_path / "work" / "myproj"
    real.mkdir(parents=True)
    session_dir = projects / baseline.slug_for(real)
    session_dir.mkdir(parents=True)
    lines = [
        json.dumps({"type": "user", "message": {"content": "hi"}}),
        json.dumps({
            "type": "assistant", "timestamp": "2026-09-11T10:00:00Z",
            "message": {"model": "claude-opus-5", "usage": {
                "input_tokens": 10, "cache_read_input_tokens": 500,
                "cache_creation_input_tokens": 100, "output_tokens": 40}},
        }),
        json.dumps({
            "type": "assistant", "timestamp": "2026-09-20T10:00:00Z",
            "message": {"model": "claude-opus-5", "usage": {
                "input_tokens": 5, "output_tokens": 5}},
        }),
        "garbage not json",
    ]
    (session_dir / "s1.jsonl").write_text("\n".join(lines))

    sessions = baseline.scan_projects([real], projects_dir=projects)
    assert len(sessions) == 1
    assert sessions[0].messages == 2
    assert sessions[0].output_tokens == 45

    import datetime as dt
    windowed = baseline.scan_projects(
        [real], since=dt.date(2026, 9, 11), until=dt.date(2026, 9, 12),
        projects_dir=projects,
    )
    assert windowed[0].messages == 1
    assert windowed[0].total == 10 + 500 + 100 + 40


def test_cost_weighting_reflects_what_is_actually_paid():
    """Summing the four token kinds says a session that read 479 million cached
    tokens cost eighty times what it did."""
    from decomp.llm.baseline import weighted

    cache_heavy = weighted(input_tokens=3_000, cache_read=479_000_000,
                           cache_write=4_400_000, output=1_365_000)
    raw = 3_000 + 479_000_000 + 4_400_000 + 1_365_000
    assert cache_heavy < raw / 5

    # Output is the expensive side, so it dominates a short exchange.
    assert weighted(0, 0, 0, 1000) > weighted(1000, 0, 0, 0)
    assert weighted(0, 1000, 0, 0) < weighted(1000, 0, 0, 0)


def test_the_baseline_states_what_it_includes(tmp_path):
    """A figure that counts unrelated work flatters whatever it is compared
    against, so it should say so."""
    from decomp.llm.baseline import BaselineReport, SessionUsage

    report = BaselineReport(
        sessions=[SessionUsage(session="s", path=tmp_path, messages=10,
                               input_tokens=100, output_tokens=50)],
        verified=5,
    )
    text = report.brief()
    assert "caveat" in text
    assert "not only the work being compared" in text
    assert "cost-weighted" in text
