from __future__ import annotations

from decomp.adapters.oracle.base import (
    DIVERGED,
    VERIFIED,
    OraclePlan,
    OracleVerdict,
)
from decomp.adapters.target.rawimage import (
    RawImageLoader,
    XexLoader,
    detect,
    get_loader,
)


# -------------------------------------------------------------------- target
def test_a_xex_container_is_recognised_and_flagged(tmp_path):
    """Pointing at the encrypted container is a mistake worth catching at import,
    not three stages later when every address turns out wrong."""
    path = tmp_path / "default.xex"
    path.write_bytes(b"XEX2" + b"\x00" * 60)

    loader = detect(path)
    assert loader.id == "xex"
    image = loader.load(path, {})
    assert image.base == 0x82000000
    assert image.platform == "xbox360"
    assert any("encrypted" in note for note in image.notes)


def test_an_extracted_image_is_not_flagged(tmp_path):
    path = tmp_path / "default_82000000.bin"
    path.write_bytes(b"\x38\x60\x00\x00" * 16)
    image = XexLoader().load(path, {"base_addr": 0x82000000})
    assert not any("encrypted" in note for note in image.notes)


def test_an_elf_is_recognised(tmp_path):
    path = tmp_path / "prog.elf"
    path.write_bytes(b"\x7fELF" + b"\x00" * 60)
    assert detect(path).id == "elf"


def test_anything_else_falls_back_to_a_flat_image(tmp_path):
    path = tmp_path / "blob.bin"
    path.write_bytes(b"\x00" * 32)
    loader = detect(path)
    assert loader.id == "rawimage"
    image = loader.load(path, {"base_addr": "0x10000000", "arch": "mips"})
    assert image.base == 0x10000000     # accepts a string, as config gives it
    assert image.arch == "mips"


def test_the_image_is_hashed_so_a_swap_is_visible(tmp_path):
    path = tmp_path / "a.bin"
    path.write_bytes(b"one")
    first = RawImageLoader().load(path, {})
    path.write_bytes(b"two")
    second = RawImageLoader().load(path, {})
    assert first.sha256 != second.sha256


def test_helper_prefixes_cover_the_register_save_stubs():
    """A decompiler that models these as ordinary functions loses the first
    argument, and every offset read from the result is wrong."""
    prefixes = RawImageLoader().helper_prefixes()
    for stub in ("__savegprlr_", "__restgprlr_", "__savefpr_", "__savevmx_"):
        assert stub in prefixes


def test_a_flat_image_reports_no_entry_points():
    """An honest empty answer: a flat image has no symbol table, and for a
    recompiled target the lifted corpus is a better source anyway."""
    assert RawImageLoader().entry_points(None) == []


def test_loaders_are_selectable_by_name():
    assert get_loader("xex").id == "xex"
    assert get_loader("elf").id == "elf"
    assert get_loader("nonsense").id == "rawimage"


def test_import_detects_the_loader(project, tmp_path):
    from decomp.pipeline.importer import import_image

    path = tmp_path / "default.xex"
    path.write_bytes(b"XEX2" + b"\x00" * 60)
    result = import_image(project, path=path)
    assert "xex" in result.brief()
    assert "encrypted" in result.brief()
    assert project.db.scalar("SELECT adapter FROM target") == "xex"


def test_an_explicit_specific_loader_wins(project, tmp_path):
    from decomp.pipeline.importer import import_image

    project.config["project"]["target_adapter"] = "elf"
    path = tmp_path / "thing.bin"
    path.write_bytes(b"XEX2" + b"\x00" * 60)
    import_image(project, path=path)
    assert project.db.scalar("SELECT adapter FROM target") == "elf"


# -------------------------------------------------------------------- oracle
def test_a_plan_without_a_control_is_not_ready():
    """A comparison that cannot disagree has not verified anything."""
    assert not OraclePlan(candidates=[1, 2], controls=[]).ready
    assert not OraclePlan(candidates=[], controls=[3]).ready
    assert OraclePlan(candidates=[1], controls=[3]).ready


def test_a_verdict_over_zero_comparisons_is_not_conclusive():
    """The shape of a run that looks green and proved nothing."""
    assert not OracleVerdict(addr=1, result=VERIFIED, compared=0).conclusive
    assert OracleVerdict(addr=1, result=VERIFIED, compared=500).conclusive
    assert OracleVerdict(addr=1, result=DIVERGED, compared=1).conclusive
    assert not OracleVerdict(addr=1, result="uncalled", compared=0).conclusive


def test_the_shadow_oracle_reports_a_missing_control(project):
    from decomp.adapters.oracle.shadow import ShadowOracle

    plan = ShadowOracle(project).prepare([0x1000])
    assert not plan.ready
    assert any("cannot demonstrate" in note for note in plan.notes)


def test_the_shadow_oracle_arms_verified_ports_as_controls(project, tmp_path):
    from decomp.adapters.oracle.shadow import ShadowOracle

    path = tmp_path / "p.inc"
    path.write_text("x")
    project.db.upsert(
        "port", {"addr": 0x2000, "path": str(path), "status": "verified"}, "addr"
    )
    plan = ShadowOracle(project).prepare([0x1000])
    assert plan.controls == [0x2000]
    assert plan.ready


def test_a_divergence_fragment_carries_the_disagreement_not_the_log(project):
    from decomp.adapters.oracle.shadow import ShadowOracle

    oracle = ShadowOracle(project)
    verdict = OracleVerdict(
        addr=0x82B2FE00, result=DIVERGED, compared=120, skipped=8,
        detail="diverges in memory at 707BFB20+1 (lifted 34, native A6)",
    )
    fragment = oracle.divergence_fragment(verdict)
    assert "707BFB20" in fragment
    assert "120 call(s) compared" in fragment
    assert "8 call(s) were skipped" in fragment
    assert len(fragment) < 600

    # Nothing to say about a port that did not diverge.
    assert oracle.divergence_fragment(
        OracleVerdict(addr=1, result=VERIFIED, compared=9)
    ) == ""
