from __future__ import annotations

import pytest

from decomp.queue import difficulty, families, tiers


# --------------------------------------------------------------------- tiers
def test_gates_decide_the_pile_before_anything_else():
    assert tiers.assign({"gate": "gate2"}) == tiers.TIER_GATE2
    assert tiers.assign({"gate": "gate3"}) == tiers.TIER_UNVERIFIABLE
    assert tiers.assign({"gate": "gate1"}) == tiers.TIER_GATE1
    assert tiers.assign({"addr": 5}, legacy={5}) == tiers.TIER_LEGACY


def test_register_only_functions_are_worth_it_only_when_hot():
    """Gate 4 stopped being fatal once the oracle could compare named registers,
    but a cold one still proves nothing."""
    assert tiers.assign({"gate": "gate4", "hot": 7_000_000}) == tiers.TIER_LEAF
    assert tiers.assign({"gate": "gate4", "hot": 0}) == tiers.TIER_UNVERIFIABLE


def test_never_observed_is_only_a_claim_once_a_trace_exists():
    cold = {"calls_boot": 0, "calls_play": 0, "hot": 0, "is_leaf": 1}
    assert tiers.assign(cold, have_profiles=True) == tiers.TIER_UNCALLED
    # Without a trace, "never ran" is not something the harness knows.
    assert tiers.assign(cold, have_profiles=False) == tiers.TIER_LEAF


def test_vector_and_leaf_shapes():
    hot = {"hot": 100, "calls_play": 100}
    assert tiers.assign({**hot, "vmx128": 1, "is_leaf": 1}) == tiers.TIER_VECTOR
    assert tiers.assign({**hot, "is_leaf": 1}) == tiers.TIER_LEAF
    assert tiers.assign({**hot, "is_leaf": 0}) == tiers.TIER_DEFAULT


def test_tier_ordering_puts_cheap_wins_first():
    order = [tiers.sort_key(t) for t in
             (tiers.TIER_LEAF, tiers.TIER_DEFAULT, tiers.TIER_VECTOR, tiers.TIER_GATE2)]
    assert order == sorted(order)


# ---------------------------------------------------------------- difficulty
def test_difficulty_spans_the_range():
    thunk = difficulty.score({"lifted_lines": 6}, {"stores": 1, "loops": 0})
    beast = difficulty.score(
        {"lifted_lines": 600, "vmx128": 1, "callee_count": 12, "gate2_suspects": 9},
        {"stores": 40, "loops": 6, "float_ops": 30},
    )
    assert thunk < 0.15
    assert beast > 0.9
    assert 0.0 <= thunk <= 1.0 and 0.0 <= beast <= 1.0


def test_difficulty_is_monotone_in_size():
    previous = -1.0
    for lines in (10, 50, 120, 300, 800):
        current = difficulty.score({"lifted_lines": lines}, {})
        assert current >= previous
        previous = current


def test_vector_work_costs_extra():
    plain = difficulty.score({"lifted_lines": 100}, {})
    vector = difficulty.score({"lifted_lines": 100, "vmx128": 1}, {})
    assert vector > plain


def test_model_routing_escalates_on_vector_and_on_failure():
    assert difficulty.tier_for(0.1) == "small"
    assert difficulty.tier_for(0.5) == "mid"
    assert difficulty.tier_for(0.9) == "strong"
    # Hand-checked lane arithmetic, or anything already retried, goes straight
    # to the strong model: a retry costs more than the price difference.
    assert difficulty.tier_for(0.1, vmx=True) == "strong"
    assert difficulty.tier_for(0.1, attempts=2) == "strong"


def test_only_small_scalar_ungated_functions_batch():
    easy = {"lifted_lines": 20}
    assert difficulty.batchable(easy, 0.1)
    assert not difficulty.batchable({**easy, "vmx128": 1}, 0.1)
    assert not difficulty.batchable({**easy, "gate": "gate1"}, 0.1)
    assert not difficulty.batchable({"lifted_lines": 200}, 0.1)
    assert not difficulty.batchable(easy, 0.6)


# ------------------------------------------------------------------ families
def _body(ops: list[str]) -> str:
    return "\n".join(f"\t// {op} r3,r4" for op in ops)


def test_similar_opcode_sequences_group_together():
    shape = ["mflr", "stw", "stwu", "mr", "cmplwi", "beq", "lis", "addi", "stw",
             "lwz", "stw", "mtlr", "blr"]
    variant = [*shape[:-2], "addi", "mtlr", "blr"]
    unrelated = ["lvx", "vmaddfp", "vperm", "stvx", "vmulfp", "vaddfp", "lvx",
                 "vsubfp", "stvx", "blr"]

    result = families.cluster({1: _body(shape), 2: _body(variant), 3: _body(unrelated)})
    assert result[1] == result[2]
    assert result[3] != result[1]


def test_tiny_functions_get_no_family():
    """Grouping thunks by accident helps nobody."""
    result = families.cluster({1: _body(["blr"]), 2: _body(["mr", "blr"])})
    assert result == {}


def test_family_ids_are_stable_across_runs():
    bodies = {i: _body(["mflr", "stw", "lwz", "addi", "stw", "mtlr", "blr", f"nop{i%2}"])
              for i in range(1, 6)}
    assert families.cluster(bodies) == families.cluster(bodies)


def test_summarize_orders_by_size():
    result = families.cluster({
        1: _body(["mflr", "stw", "lwz", "addi", "stw", "blr"]),
        2: _body(["mflr", "stw", "lwz", "addi", "stw", "blr"]),
        3: _body(["lvx", "vperm", "vmaddfp", "stvx", "vaddfp", "blr"]),
    })
    summary = families.summarize(result)
    assert summary[0].size >= summary[-1].size
    assert summary[0].members == sorted(summary[0].members)


# -------------------------------------------------------------------- stage
@pytest.fixture
def queued(project, fixtures):
    from decomp.pipeline.importer import import_lifted
    from decomp.pipeline.queue import build
    from decomp.pipeline.screen import screen

    import_lifted(project, path=fixtures / "lifted")
    project.db.execute("UPDATE function SET in_corpus=1 WHERE addr < 0x82F00000")
    screen(project)
    build(project)
    return project


def test_queue_build_assigns_tier_difficulty_and_family(queued):
    rows = queued.db.query("SELECT * FROM function WHERE in_corpus=1")
    assert rows
    for r in rows:
        assert r["tier"] in tiers.TIER_ORDER
        assert r["difficulty"] is not None


def test_queue_next_skips_gated_work_by_default(queued):
    from decomp.pipeline.queue import next_items

    result = next_items(queued, limit=10)
    addrs = {i.addr for i in result.items}
    # The fixture's bctrl function is gate 1 and must not be offered.
    assert 0x82B10200 not in addrs
    assert next_items(queued, limit=10, include_gated=True).total_open > result.total_open


def test_queue_next_reports_the_routing_decision(queued):
    from decomp.pipeline.queue import next_items

    for item in next_items(queued, limit=10).items:
        assert item.model_tier in ("small", "mid", "strong")
        assert isinstance(item.batchable, bool)


def test_queue_report_separates_settled_from_work_to_do(queued):
    from decomp.pipeline.queue import report, set_status

    before = report(queued).totals
    open_addr = next(
        r["addr"] for r in queued.db.query(
            "SELECT addr FROM function WHERE in_corpus=1 AND gate IS NULL"
        )
    )
    set_status(queued, open_addr, status="verified")
    after = report(queued).totals
    assert after["settled"] == before["settled"] + 1
    assert after["to do"] == before["to do"] - 1


def test_set_status_rejects_unknown_values(queued):
    from decomp.pipeline.queue import set_status

    with pytest.raises(ValueError, match="unknown status"):
        set_status(queued, 0x82B10000, status="probably-fine")
    with pytest.raises(ValueError, match="nothing to set"):
        set_status(queued, 0x82B10000)


def test_building_an_empty_corpus_is_an_error(project):
    from decomp.pipeline.queue import build

    with pytest.raises(ValueError, match="nothing in the corpus"):
        build(project)


# ------------------------------------------------------------------- effort
def test_effort_scales_with_the_tier():
    """Output is billed at several times input, and on a simple port the
    reasoning dwarfs the answer: one measured call produced 25,377 output
    tokens for an answer of about two thousand."""
    assert difficulty.effort_for("small") == "low"
    assert difficulty.effort_for("mid") == "medium"
    assert difficulty.effort_for("strong") == "high"


def test_a_retry_thinks_harder():
    """The cheap pass already failed, so spending more on the second is the
    correct trade."""
    assert difficulty.effort_for("small", retrying=True) == "high"
    assert difficulty.effort_for("mid", retrying=True) == "high"


def test_an_unknown_tier_gets_a_middle_effort():
    assert difficulty.effort_for("nonsense") == "medium"


# ---------------------------------------------------------------- work states
def test_a_written_port_is_not_offered_again(queued):
    """Treating "not yet verified" as "still open" made the queue hand back the
    same functions round after round, and the port loop re-author work it had
    already done."""
    from decomp.pipeline.queue import next_items, set_status

    first = next_items(queued, limit=1).items
    assert first
    addr = first[0].addr

    set_status(queued, addr, status="written")
    offered = {i.addr for i in next_items(queued, limit=20).items}
    assert addr not in offered


def test_work_in_flight_is_counted_separately_from_work_to_do(queued):
    from decomp.pipeline.queue import report, set_status

    addrs = [i.addr for i in next_items_all(queued)][:2]
    before = report(queued).totals
    set_status(queued, addrs[0], status="written")
    set_status(queued, addrs[1], status="verified")
    after = report(queued).totals

    assert after["awaiting a session"] == before["awaiting a session"] + 1
    assert after["settled"] == before["settled"] + 1
    assert after["to do"] == before["to do"] - 2


def next_items_all(project):
    from decomp.pipeline.queue import next_items

    return next_items(project, limit=50).items


def test_a_diverged_port_is_offered_again(queued):
    from decomp.pipeline.queue import next_items, set_status

    addr = next_items(queued, limit=1).items[0].addr
    set_status(queued, addr, status="divergent", attempts=1)
    assert addr in {i.addr for i in next_items(queued, limit=20).items}


def test_a_port_that_keeps_diverging_is_left_alone(queued):
    """Three failed attempts is a signal to stop, not a reason to keep paying."""
    from decomp.pipeline.queue import MAX_ATTEMPTS, next_items, set_status

    addr = next_items(queued, limit=1).items[0].addr
    set_status(queued, addr, status="divergent", attempts=MAX_ATTEMPTS)
    assert addr not in {i.addr for i in next_items(queued, limit=20).items}


def test_gated_and_uncalled_work_is_settled(queued):
    from decomp.pipeline.queue import next_items, set_status

    addrs = [i.addr for i in next_items(queued, limit=3).items]
    for addr, status in zip(addrs, ("gate1", "uncalled", "needs_human"), strict=False):
        set_status(queued, addr, status=status)
    offered = {i.addr for i in next_items(queued, limit=20).items}
    assert not offered & set(addrs)
