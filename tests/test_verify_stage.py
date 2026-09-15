from __future__ import annotations

import json

import pytest

from decomp.pipeline.promote import run as run_promote
from decomp.pipeline.session import run as run_session
from decomp.pipeline.verify import run as run_verify

PORT_SOURCE = """\
REX_FUNC(Native) {
  REX_STORE_U32(ctx.r3.u32 + 8, ctx.r4.u32);
  ctx.r3.u32 = 0x14;
}
"""


@pytest.fixture
def oracle_project(project, tmp_path):
    """A project with one built port and a session command that does nothing."""
    ports = project.sub("ports")
    path = ports / "sub_82B28A00.inc"
    path.write_text(PORT_SOURCE)

    project.db.upsert("function", {"addr": 0x82B28A00, "lifted_lines": 40,
                                   "status": "verified"}, "addr")
    project.db.upsert("port", {"addr": 0x82B28A00, "path": str(path),
                               "status": "verified", "build_id": 1}, "addr")
    project.db.execute(
        "INSERT INTO build (id, host, ok, nm_symbols_ok, artifact_path) "
        "VALUES (1,'local',1,1,'/bin/sh')"
    )
    project.config["session"] = {"command": "true", "log_path": str(tmp_path / "s.log")}
    return project


# ------------------------------------------------------------------ refusals
def test_a_session_without_a_build_is_refused(project):
    project.config["session"] = {"command": "true"}
    result = run_session(project, controls=0)
    assert not result.ok
    assert "no verified build" in result.refused


def test_a_session_against_a_stale_build_is_refused(oracle_project):
    """The armed set and the binary must agree, or every verdict describes
    code that was not running."""
    path = oracle_project.sub("ports") / "sub_82B28B78.inc"
    path.write_text(PORT_SOURCE)
    oracle_project.db.upsert(
        "port", {"addr": 0x82B28B78, "path": str(path), "status": "written",
                 "build_id": None}, "addr",
    )
    result = run_session(oracle_project, controls=0)
    assert not result.ok
    assert "not in build" in result.refused
    assert "sub_82B28B78" in result.refused


def test_stale_can_be_overridden_deliberately(oracle_project):
    path = oracle_project.sub("ports") / "sub_82B28B78.inc"
    path.write_text(PORT_SOURCE)
    oracle_project.db.upsert(
        "port", {"addr": 0x82B28B78, "path": str(path), "status": "written"}, "addr"
    )
    result = run_session(oracle_project, controls=0, allow_stale=True)
    assert result.session_id is not None


def test_a_session_with_no_armed_control_is_refused(project, tmp_path):
    """A session in which nothing can fail cannot verify anything."""
    project.config["session"] = {"command": "true", "log_path": str(tmp_path / "s.log")}
    project.db.execute("INSERT INTO build (id, host, ok) VALUES (1,'local',1)")
    result = run_session(project, controls=2)
    assert not result.ok
    assert "no negative control" in result.refused
    assert "--controls 0" in result.refused


def test_controls_are_armed_and_recorded(oracle_project):
    result = run_session(oracle_project, controls=1)
    assert result.session_id is not None
    assert any(c.applied for c in result.controls)
    stored = json.loads(oracle_project.db.scalar(
        "SELECT negative_controls_json FROM session WHERE id=?", (result.session_id,)
    ))
    assert stored and stored[0]["applied"] is True


# -------------------------------------------------------------------- verify
def _session_with_log(project, text: str, controls: list[dict]):
    log = project.sub("sessions") / "t.log"
    log.write_text(text)
    cur = project.db.execute(
        "INSERT INTO session (host, profile, log_path, negative_controls_json, started) "
        "VALUES ('local','play',?,?,'now')",
        (str(log), json.dumps(controls)),
    )
    return int(cur.lastrowid)


def test_verdicts_are_not_recorded_when_a_control_escapes(project):
    """The whole point: a control that was not caught invalidates the run."""
    sid = _session_with_log(
        project,
        "sub_82B28A00 compared=500 skipped=0 clean\n"
        "sub_82B28B78 compared=500 skipped=0 clean\n",
        [{"addr": 0x82B28B78, "kind": "offset", "applied": True}],
    )
    result = run_verify(project, session_id=sid)
    assert not result.trusted
    assert "not caught" in result.control_summary
    assert project.db.scalar("SELECT COUNT(*) FROM verdict") == 0


def test_verdicts_are_recorded_when_the_control_is_caught(project):
    sid = _session_with_log(
        project,
        "sub_82B28A00 compared=500 skipped=0 clean\n"
        "sub_82B28B78 diverges in register r3 (lifted 01, native 02)\n",
        [{"addr": 0x82B28B78, "kind": "offset", "applied": True}],
    )
    result = run_verify(project, session_id=sid)
    assert result.trusted
    assert result.recorded == 1                      # the control is not work
    assert project.db.scalar(
        "SELECT status FROM function WHERE addr=?", (0x82B28A00,)
    ) == "verified"
    assert project.db.scalar("SELECT trusted FROM session WHERE id=?", (sid,)) == 1


def test_a_session_with_no_control_records_nothing_by_default(project):
    sid = _session_with_log(project, "sub_82B28A00 compared=9 skipped=0 clean\n", [])
    result = run_verify(project, session_id=sid)
    assert not result.trusted
    assert "no negative control" in result.control_summary
    assert project.db.scalar("SELECT COUNT(*) FROM verdict") == 0


def test_the_control_requirement_can_be_waived_explicitly(project):
    sid = _session_with_log(project, "sub_82B28A00 compared=9 skipped=0 clean\n", [])
    result = run_verify(project, session_id=sid, require_controls=False)
    assert result.trusted and result.recorded == 1


def test_divergence_is_kept_on_the_function(project):
    sid = _session_with_log(
        project,
        "sub_82B28A00 diverges in memory at 707BFB20+1 (lifted 34, native A6)\n"
        "sub_82B28B78 diverges in register r3\n",
        [{"addr": 0x82B28B78, "kind": "result", "applied": True}],
    )
    run_verify(project, session_id=sid)
    row = project.db.one("SELECT * FROM function WHERE addr=?", (0x82B28A00,))
    assert row["status"] == "divergent"
    assert "707BFB20" in row["last_divergence"]


# ------------------------------------------------------------------- promote
def _verified(project, addr: int, lines: int, compared: list[int]):
    project.db.upsert("function", {"addr": addr, "lifted_lines": lines,
                                   "status": "verified"}, "addr")
    for i, n in enumerate(compared):
        project.db.execute(
            "INSERT INTO session (id, host, profile, trusted, started) "
            "VALUES (?,?,?,1,'now')", (100 + i, "local", f"p{i}")
        ) if not project.db.one("SELECT 1 FROM session WHERE id=?", (100 + i,)) else None
        project.db.execute(
            "INSERT INTO verdict (session_id, addr, result, compared) VALUES (?,?,?,?)",
            (100 + i, addr, "verified", n),
        )


def test_promotion_uses_the_weaker_profile(project):
    """Comfortably exercised in one session and barely touched in another means
    it has only been shown to work in the first."""
    _verified(project, 0x1000, lines=40, compared=[5000, 12])
    result = run_promote(project)
    decision = result.decisions[0]
    assert not decision.promoted
    assert decision.calls == 12
    assert "fewer than" in decision.reason


def test_promotion_scales_with_body_size(project):
    # 200 calls is plenty for a 40-line body and thin for a 600-line one.
    _verified(project, 0x1000, lines=40, compared=[200])
    _verified(project, 0x2000, lines=600, compared=[200])
    result = run_promote(project)
    by_addr = {d.addr: d for d in result.decisions}
    assert by_addr[0x1000].promoted
    assert not by_addr[0x2000].promoted
    assert "per line" in by_addr[0x2000].reason


def test_promotion_ignores_untrusted_sessions(project):
    project.db.upsert("function", {"addr": 0x3000, "lifted_lines": 10,
                                   "status": "verified"}, "addr")
    project.db.execute(
        "INSERT INTO session (id, host, profile, trusted, started) "
        "VALUES (200,'local','p',0,'now')"
    )
    project.db.execute(
        "INSERT INTO verdict (session_id, addr, result, compared) "
        "VALUES (200, 0x3000, 'verified', 99999)"
    )
    result = run_promote(project)
    assert result.promoted == 0
    assert result.skipped_untrusted == 1


def test_held_ports_are_marked_thin_not_promoted(project):
    _verified(project, 0x1000, lines=40, compared=[5])
    run_promote(project)
    assert project.db.scalar(
        "SELECT status FROM function WHERE addr=?", (0x1000,)
    ) == "thin"


def test_dry_run_decides_without_writing(project):
    _verified(project, 0x1000, lines=40, compared=[5000])
    result = run_promote(project, dry_run=True)
    assert result.promoted == 1
    assert project.db.scalar(
        "SELECT status FROM function WHERE addr=?", (0x1000,)
    ) == "verified"
