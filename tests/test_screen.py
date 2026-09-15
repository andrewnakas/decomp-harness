from __future__ import annotations

import pytest

from decomp.adapters.screen.rexglue_census import CensusRules, RexGlueCensus

ENTRY_STORE = """
DEFINE_REX_FUNC(sub_82B10000) {
	// stw r4,8(r3)
	REX_STORE_U32(ctx.r3.u32 + 8, ctx.r4.u32);
	// sth r5,12(r3)
	REX_STORE_U16(ctx.r3.u32 + 12, ctx.r5.u16);
	return;
}
"""

DERIVED_STORE = """
DEFINE_REX_FUNC(sub_82B10100) {
	// lwz r9,48(r3)
	ctx.r9.u64 = REX_LOAD_U32(ctx.r3.u32 + 48);
	// stw r4,0(r9)
	REX_STORE_U32(ctx.r9.u32 + 0, ctx.r4.u32);
	return;
}
"""

LOOP_STORE = """
DEFINE_REX_FUNC(sub_82B10200) {
	// li r9,0
	ctx.r9.s64 = 0;
loc_82B10210:
	// stw r4,0(r9)
	REX_STORE_U32(ctx.r9.u32 + 0, ctx.r4.u32);
	// addi r9,r9,4
	ctx.r9.s64 = ctx.r9.s64 + 4;
	// bdnz loc_82B10210
	goto loc_82B10210;
	return;
}
"""

INDIRECT = """
DEFINE_REX_FUNC(sub_82B10300) {
	// stw r4,8(r3)
	REX_STORE_U32(ctx.r3.u32 + 8, ctx.r4.u32);
	// bctrl
	REX_CALL_INDIRECT_FUNC(ctx.ctr.u32);
	return;
}
"""

TIMEBASE = """
DEFINE_REX_FUNC(sub_82B10400) {
	// mftb r11
	ctx.r11.u64 = REX_QUERY_TIMEBASE();
	// stw r11,8(r3)
	REX_STORE_U32(ctx.r3.u32 + 8, ctx.r11.u32);
	return;
}
"""

LOCK = """
DEFINE_REX_FUNC(sub_82B10500) {
	// bl 0x82f60000
	__imp__RtlEnterCriticalSection(ctx, base);
	// stw r4,8(r3)
	REX_STORE_U32(ctx.r3.u32 + 8, ctx.r4.u32);
	return;
}
"""

NO_STORES = """
DEFINE_REX_FUNC(sub_82B10600) {
	// lwz r3,0(r3)
	ctx.r3.u64 = REX_LOAD_U32(ctx.r3.u32 + 0);
	// blr
	return;
}
"""


@pytest.fixture
def screener():
    return RexGlueCensus()


def test_entry_register_stores_pass(screener):
    r = screener.screen(0x82B10000, ENTRY_STORE)
    assert r.gate == "pass"
    assert len(r.stores) == 2
    assert all(s.base == "entry" for s in r.stores)
    assert [w["len"] for w in r.suggested_windows] == [4, 2]
    assert [w["offset"] for w in r.suggested_windows] == [8, 12]
    assert not any(w["needs_deref"] for w in r.suggested_windows)


def test_a_base_loaded_during_the_call_is_a_suspect_not_a_failure(screener):
    """The audio project's verified command-queue producer stores through a
    loaded pointer 17 times; gating on that would have rejected it."""
    r = screener.screen(0x82B10100, DERIVED_STORE)
    assert r.gate == "pass"
    assert r.census["gate2_suspects"] == 1
    assert r.suggested_windows[0]["needs_deref"] is True
    assert "read before the call" in " ".join(r.reasons)


def test_stores_inside_a_loop_are_gate2(screener):
    r = screener.screen(0x82B10200, LOOP_STORE)
    assert r.gate == "gate2"
    assert "loop" in r.reasons[0]
    assert r.census["loops"] == 1


def test_indirect_calls_are_gate1(screener):
    r = screener.screen(0x82B10300, INDIRECT)
    assert r.gate == "gate1"
    assert "indirect call" in r.reasons[0]


def test_locks_are_gate1(screener):
    assert screener.screen(0x82B10500, LOCK).gate == "gate1"


def test_timebase_outranks_everything(screener):
    """Nondeterminism cannot be compared even when the writes are clean."""
    r = screener.screen(0x82B10400, TIMEBASE)
    assert r.gate == "gate3"


def test_a_function_with_no_stores_is_gate4(screener):
    r = screener.screen(0x82B10600, NO_STORES)
    assert r.gate == "gate4"
    assert "result registers" in r.reasons[0]


def test_budgets_are_enforced():
    tight = RexGlueCensus(window_budget_spans=1)
    assert tight.screen(0x82B10000, ENTRY_STORE).gate == "gate2"

    narrow = RexGlueCensus(window_budget_bytes=4)
    assert narrow.screen(0x82B10000, ENTRY_STORE).gate == "gate2"


def test_an_empty_body_cannot_be_screened(screener):
    r = screener.screen(0x1, "")
    assert r.gate == "gate2"
    assert "no body" in r.reasons[0]


def test_rules_are_data_not_code():
    """Swapping the patterns retargets the screener without touching it."""
    rules = CensusRules.load_from({
        "gate1_patterns": {"custom trap": r"MY_OWN_TRAP"},
        "gate3_patterns": {},
    })
    screener = RexGlueCensus(rules=rules)
    assert screener.screen(0x82B10300, INDIRECT).gate == "pass"
    assert screener.screen(0x1, "MY_OWN_TRAP();\nREX_STORE_U32(ctx.r3.u32 + 0, 1);").gate \
        == "gate1"


def test_screen_stage_persists_gates_and_reasons(project, fixtures):
    from decomp.pipeline.importer import import_lifted
    from decomp.pipeline.screen import screen as run_screen

    import_lifted(project, path=fixtures / "lifted")
    project.db.execute("UPDATE function SET in_corpus=1")
    res = run_screen(project)

    assert res.screened >= 3
    row = project.db.one("SELECT * FROM gate WHERE addr=?", (0x82B10200,))
    assert row["gate"] == "gate1"          # the fixture's bctrl
    fn = project.db.one("SELECT * FROM function WHERE addr=?", (0x82B10200,))
    assert fn["gate"] == "gate1"
    assert fn["gate_reason"]

    # A passing function records no gate, so later stages can filter on NULL.
    passing = [a for a, g in
               ((r["addr"], r["gate"]) for r in project.db.query("SELECT addr, gate FROM gate"))
               if g == "pass"]
    for addr in passing:
        assert project.db.scalar("SELECT gate FROM function WHERE addr=?", (addr,)) is None
