from __future__ import annotations

from decomp.adapters.build.base import ArtifactCheck
from decomp.adapters.build.cmake_ninja import extract_diagnostics
from decomp.adapters.session.shadow import parse_log
from decomp.core.config import Host
from decomp.core.remote import Transport
from decomp.verify import controls as controls_mod

PORT_SOURCE = """\
namespace port_82B28A00 {
REX_FUNC(Native) {
  REX_STORE_U32(ctx.r3.u32 + 8, ctx.r4.u32);
  ctx.r3.u32 = 0x14;
}
}
SKATE3_PORT(82B28A00, kPortVerified, kReturnR3)
"""


# ----------------------------------------------------------------- transport
def test_local_transport_runs_and_reports_failure():
    t = Transport(host=Host(name="local"))
    assert t.run("echo hi").stdout.strip() == "hi"

    # A failing command must stay failed: a build script that hid its status
    # behind a pipe once sent a stale binary into a session.
    bad = t.run("echo oops >&2; exit 7")
    assert not bad.ok and bad.returncode == 7
    assert "oops" in bad.tail(5)


def test_transport_reads_timestamps_and_existence(tmp_path):
    t = Transport(host=Host(name="local"))
    f = tmp_path / "artifact"
    f.write_text("x")
    assert t.exists(str(f))
    assert isinstance(t.mtime(str(f)), float)
    assert not t.exists(str(tmp_path / "absent"))
    assert t.mtime(str(tmp_path / "absent")) is None


def test_dry_run_makes_no_changes(tmp_path):
    t = Transport(host=Host(name="local"), dry_run=True)
    result = t.run(f"touch {tmp_path / 'should-not-exist'}")
    assert result.ok
    assert not (tmp_path / "should-not-exist").exists()


# --------------------------------------------------------------------- build
def test_artifact_check_requires_existence_freshness_and_symbols():
    assert not ArtifactCheck(path="x").ok
    assert "does not exist" in ArtifactCheck(path="x").why()

    stale = ArtifactCheck(path="x", exists=True, fresh=False)
    assert not stale.ok
    assert "older than its sources" in stale.why()

    missing = ArtifactCheck(path="x", exists=True, fresh=True,
                            expected_symbols=3, found_symbols=1,
                            missing=["port_A", "port_B"])
    assert not missing.ok
    assert "absent" in missing.why()

    good = ArtifactCheck(path="x", exists=True, fresh=True,
                         expected_symbols=2, found_symbols=2)
    assert good.ok and good.why() == "verified"


def test_diagnostics_keep_the_errors_and_drop_the_progress():
    log = """
[1/200] Building CXX object foo.o
[2/200] Building CXX object bar.o
/long/path/to/src/port.inc:12:5: error: use of undeclared identifier 'ctx2'
/long/path/to/src/port.inc:14:9: warning: unused variable 'x'
FAILED: skate3
[3/200] Building CXX object baz.o
"""
    out = extract_diagnostics(log)
    assert "port.inc:12: error: use of undeclared identifier 'ctx2'" in out
    assert "Building CXX object" not in out
    assert "/long/path/to" not in out          # paths a model cannot act on
    assert "FAILED" in out


def test_diagnostics_are_capped():
    log = "\n".join(f"f.c:{i}:1: error: problem {i}" for i in range(100))
    out = extract_diagnostics(log, limit=5)
    assert len(out.splitlines()) <= 6
    assert "omitted" in out


# ------------------------------------------------------------------- session
def test_log_parsing_extracts_verdicts():
    log = """
sub_82B28A00 compared=6706 skipped=0 clean
sub_82B28B78 compared=1 skipped=0 clean
sub_82B2FE00 diverges in memory at 707BFB20+1 (lifted 34, native A6)
sub_82B7F828 window budget overflow
50912345 total calls
"""
    summary = parse_log(log)
    by_addr = {v.addr: v for v in summary.verdicts}
    assert by_addr[0x82B28A00].result == "verified"
    assert by_addr[0x82B28A00].compared == 6706
    assert by_addr[0x82B2FE00].result == "diverged"
    assert "707BFB20" in by_addr[0x82B2FE00].divergence
    assert by_addr[0x82B7F828].result == "overflow"
    assert summary.calls_total == 50912345


def test_a_clean_report_with_no_comparisons_is_not_a_pass():
    """The shape of a session that looks green and proved nothing."""
    summary = parse_log("sub_82B28A00 compared=0 skipped=412 clean")
    assert summary.verdicts[0].result == "uncalled"
    assert any("compared nothing" in n for n in summary.notes)


# ------------------------------------------------------------------ controls
def test_each_mutation_kind_changes_behaviour():
    kinds = set()
    for seed in range(40):
        result = controls_mod.mutate(PORT_SOURCE, seed=seed)
        assert result is not None
        kind, mutated, original, replacement = result
        kinds.add(kind)
        assert mutated != PORT_SOURCE
        assert replacement in mutated
    assert kinds == {"offset", "value", "result"}


def test_a_port_with_no_mutation_site_yields_no_control():
    assert controls_mod.mutate("// nothing here") is None


def test_an_unapplied_control_is_recorded_not_hidden(tmp_path):
    """A control whose mutation never applied passes as an unmodified port,
    which is how a run looks validated while testing nothing."""
    port = tmp_path / "sub_00000001.inc"
    port.write_text("// no mutation site in this file")
    controls = controls_mod.build_controls([(1, port)], tmp_path / "c", count=1)
    assert len(controls) == 1
    assert not controls[0].applied
    assert not controls_mod.confirm_applied(controls[0])
    assert "no mutation site" in controls[0].description


def test_confirm_applied_checks_the_file_that_will_be_built(tmp_path):
    port = tmp_path / "sub_82B28A00.inc"
    port.write_text(PORT_SOURCE)
    controls = controls_mod.build_controls([(0x82B28A00, port)], tmp_path / "c",
                                           count=1, seed=1)
    assert controls[0].applied
    assert controls_mod.confirm_applied(controls[0])

    # Silently reverting the mutation must not leave it looking armed.
    controls[0].mutated_path.write_text(PORT_SOURCE)
    assert not controls_mod.confirm_applied(controls[0])


def test_a_control_only_passes_by_being_caught(tmp_path):
    port = tmp_path / "sub_82B28A00.inc"
    port.write_text(PORT_SOURCE)
    controls = controls_mod.build_controls([(0x82B28A00, port)], tmp_path / "c",
                                           count=1, seed=1)

    caught = controls_mod.evaluate(controls, diverged={0x82B28A00})
    assert caught.ok and caught.caught == [0x82B28A00]

    missed = controls_mod.evaluate(controls, diverged=set())
    assert not missed.ok
    assert "not caught" in missed.why()


def test_no_controls_at_all_is_untrusted(tmp_path):
    outcome = controls_mod.evaluate([], diverged={1, 2, 3})
    assert not outcome.ok
    assert "proves nothing" in outcome.why()
