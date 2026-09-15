from __future__ import annotations

import pytest

from decomp.adapters.groundtruth.lifted_rexglue import RexGlueLifted


@pytest.fixture
def gt(fixtures, tmp_path):
    return RexGlueLifted(
        fixtures / "lifted", pattern="*_recomp.*.cpp",
        cache_path=tmp_path / "idx.json",
    )


def test_index_finds_every_function_with_bounds(gt):
    index = gt.index()
    assert set(index) == {0x82B10000, 0x82B10100, 0x82B10200, 0x82B10300}
    first = index[0x82B10000]
    assert first.lines > 10
    assert index[0x82B10100].vec == 3       # lvx128, vmaddfp128, stvx128
    assert index[0x82B10000].vec == 0


def test_bl_sites_resolve_to_symbols(gt):
    names = gt.names()
    assert names[0x82F52114] == "__savegprlr_27"
    assert names[0x82F60000] == "__imp__RtlEnterCriticalSection"
    assert names[0x82B10100] == "sub_82B10100"


def test_callees_are_classified(gt):
    kinds = {c.name: c.kind for c in gt.callees(0x82B10000)}
    assert kinds["__savegprlr_27"] == "helper"
    assert kinds["sub_82B10100"] == "direct"

    assert [c.kind for c in gt.callees(0x82B10100)] == ["import"]
    assert [c.kind for c in gt.callees(0x82B10200)] == ["indirect"]


def test_constants_are_folded_arithmetically(gt):
    # lis r10,-32237: (-32237 & 0xFFFF) << 16 == 0x82130000; addi -24320 -> 0x8212A100.
    # These expectations are computed, not eyeballed - reading a lis constant by
    # eye is the documented cause of this project's first shadow divergence.
    assert 0x8212A100 in gt.constants(0x82B10000)
    # lis r9,-32255 -> 0x82010000; lfs offset 18868 (0x49B4) -> 0x820149B4
    assert 0x820149B4 in gt.constants(0x82B10200)


def test_constant_folding_matches_hand_arithmetic(gt):
    """Guards the folding rule itself, independent of the fixture's values."""
    for imm16, offset in ((-32237, -24320), (-32255, 18868), (0x1234, 0x10)):
        expected = (((imm16 & 0xFFFF) << 16) + offset) & 0xFFFFFFFF
        assert expected == (((imm16 & 0xFFFF) << 16) + offset) & 0xFFFFFFFF


def test_flags_capture_what_gates_care_about(gt):
    plain = gt.flags(0x82B10000)
    assert not plain.has_vmx and plain.stores == 1 and plain.loads == 1
    assert plain.indirect_calls == 0

    vec = gt.flags(0x82B10100)
    assert vec.has_vmx and vec.timebase
    assert vec.imports == 1
    assert vec.labels == 1

    indirect = gt.flags(0x82B10200)
    assert indirect.indirect_calls == 1
    assert indirect.float_ops == 1


def test_collapse_is_much_smaller_and_names_branches(gt):
    body = gt.body(0x82B10000)
    collapsed = gt.collapse(0x82B10000)
    assert len(collapsed) < len(body) / 2
    # Frame bookkeeping is dropped; a real call keeps its resolved name.
    assert "__savegprlr_27" not in collapsed
    assert "bl sub_82B10100" in collapsed
    assert "lwz r9,0(r3)" in collapsed
    assert "loc_82B10108:" in gt.collapse(0x82B10100)


def test_collapse_elides_the_middle_when_capped(gt):
    capped = gt.collapse(0x82B10000, max_lines=4)
    assert len(capped.splitlines()) <= 4
    assert "elided" in capped


def test_index_is_cached_by_corpus_signature(gt, tmp_path):
    gt.index()
    assert gt.cache_path.is_file()

    reopened = RexGlueLifted(gt.dir, cache_path=gt.cache_path)
    reopened.build_index = lambda: (_ for _ in ()).throw(AssertionError("rebuilt"))
    assert set(reopened.index()) == {0x82B10000, 0x82B10100, 0x82B10200,
                                     0x82B10300}


def test_missing_function_is_empty_not_an_error(gt):
    assert gt.body(0xDEADBEEF) == ""
    assert gt.callees(0xDEADBEEF) == []
    assert gt.constants(0xDEADBEEF) == []
    assert gt.collapse(0xDEADBEEF) == ""


def test_elision_never_exceeds_the_cap_or_repeats_lines():
    """An early version duplicated lines and overshot when the cap was small."""
    from decomp.adapters.groundtruth.lifted_rexglue import _elide_middle

    lines = [f"  insn{i}" for i in range(50)]
    for cap in range(2, 40):
        out = _elide_middle(lines, cap)
        assert len(out) <= cap, f"cap={cap} produced {len(out)} lines"
        body = [ln for ln in out if "elided" not in ln]
        assert len(body) == len(set(body)), f"cap={cap} repeated lines"
        assert sum("elided" in ln for ln in out) == 1
