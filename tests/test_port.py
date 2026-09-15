from __future__ import annotations

import json

import pytest

from decomp.llm.schemas import PortAnswer, json_schema, parse_batch_answer, parse_port_answer
from decomp.port import emit, lint


def answer(**kw) -> PortAnswer:
    base = dict(
        addr="82B28A00",
        code="REX_STORE_U32(ctx.r3.u32 + 8, ctx.r4.u32);",
        windows=[{"base": "r3", "offset": 8, "length": 4}],
        result_registers=["r3"],
    )
    base.update(kw)
    return PortAnswer.model_validate(base)


# ------------------------------------------------------------------ schemas
def test_schema_is_accepted_and_complete():
    schema = json_schema(PortAnswer)
    props = schema["properties"]
    for required in ("addr", "code", "windows", "result_registers", "blocked", "needs"):
        assert required in props
    assert "code" in schema["required"]


def test_malformed_answers_are_rejected_with_a_usable_message():
    with pytest.raises(ValueError, match="no structured output"):
        parse_port_answer(None)
    with pytest.raises(ValueError, match="code"):
        parse_port_answer({"addr": "82B28A00"})


def test_batch_answers_parse_either_shape():
    one = {"addr": "1", "code": "x;"}
    assert len(parse_batch_answer({"ports": [one, one]})) == 2
    assert len(parse_batch_answer([one])) == 1
    assert len(parse_batch_answer(one)) == 1


# --------------------------------------------------------------------- lint
def test_a_correct_answer_passes():
    assert lint.check(answer(), 0x82B28A00).ok


def test_wrong_address_is_caught():
    result = lint.check(answer(addr="DEADBEEF"), 0x82B28A00)
    assert not result.ok
    assert any(i.check == "addr" for i in result.issues)


def test_scaffolding_is_rejected():
    """The harness writes the namespace and the macro; a duplicate will not build."""
    for bad in ("namespace port_82B28A00 {\n}", "#include <x.h>", "REX_FUNC(Native) {}"):
        result = lint.check(answer(code=bad), 0x82B28A00)
        assert any(i.check == "scaffolding" for i in result.issues), bad


def test_direct_import_calls_are_rejected():
    result = lint.check(
        answer(code="__imp__RtlEnterCriticalSection(ctx, base);"), 0x82B28A00
    )
    assert any(i.check == "direct_import" for i in result.issues)


def test_an_answer_that_compares_nothing_is_rejected():
    """Windows and result registers are the only two ways a comparison can fail."""
    result = lint.check(answer(windows=[], result_registers=[]), 0x82B28A00)
    assert any(i.check == "vacuous" for i in result.issues)


def test_writes_without_windows_are_rejected():
    result = lint.check(
        answer(windows=[], result_registers=["r3"]), 0x82B28A00
    )
    assert any(i.check == "undeclared_writes" for i in result.issues)


def test_budgets_are_enforced():
    huge = [{"base": "r3", "offset": i, "length": 4} for i in range(40)]
    result = lint.check(answer(windows=huge), 0x82B28A00, budget_spans=32)
    assert any(i.check == "window_spans" for i in result.issues)

    wide = [{"base": "r3", "offset": 0, "length": 99999}]
    result = lint.check(answer(windows=wide), 0x82B28A00, budget_bytes=32768)
    assert any(i.check == "window_bytes" for i in result.issues)


def test_blocked_must_be_explained():
    result = lint.check(answer(blocked="gate2", note=""), 0x82B28A00)
    assert any(i.check == "blocked_unexplained" for i in result.issues)
    assert lint.check(answer(blocked="gate2", note="walks a list"), 0x82B28A00).ok


# The next three reproduce bugs a live model actually produced on the first
# real port this harness ran. Each would have rewound the wrong memory or
# compared nothing.
LIVE_BUG_CODE = (
    "u32 player = REX_LOAD_U32(ctx.r3.u32 + 4);\n"
    "REX_STORE_U32(player + 0x150, 0);\n"
    "ctx.r3.u32 = 0x14;"
)


def test_a_window_that_ignores_a_deref_is_caught():
    """The hint said [r3+4]+336; the answer wrote r3+336, which would rewind
    the command record instead of the object it points to."""
    result = lint.check(
        answer(code=LIVE_BUG_CODE,
               windows=[{"base": "r3", "offset": 336, "length": 4}]),
        0x82B28A00,
    )
    assert any(i.check == "window_deref" for i in result.issues)


def test_a_window_on_an_unread_register_is_caught():
    result = lint.check(
        answer(code=LIVE_BUG_CODE,
               windows=[{"base": "r3", "deref": [4], "offset": 336, "length": 4},
                        {"base": "r7", "offset": 0, "length": 4}]),
        0x82B28A00,
    )
    assert any(i.check == "window_base_unused" for i in result.issues)


def test_an_undeclared_return_value_is_caught():
    result = lint.check(
        answer(code=LIVE_BUG_CODE, result_registers=[],
               windows=[{"base": "r3", "deref": [4], "offset": 336, "length": 4}]),
        0x82B28A00,
    )
    assert any(i.check == "result_undeclared" for i in result.issues)


def test_the_corrected_form_of_that_answer_passes():
    assert lint.check(
        answer(code=LIVE_BUG_CODE, result_registers=["r3"],
               windows=[{"base": "r3", "deref": [4], "offset": 336, "length": 4}]),
        0x82B28A00,
    ).ok


def test_feedback_lists_only_the_failures():
    result = lint.check(answer(addr="BAD", windows=[], result_registers=[]), 0x82B28A00)
    feedback = result.feedback()
    assert "vacuous" in feedback
    assert "warn" not in feedback


# --------------------------------------------------------------------- emit
def test_rendered_port_has_the_expected_shape():
    text = emit.render(answer(), 0x82B28A00)
    assert "namespace port_82B28A00 {" in text
    assert "REX_FUNC(Native)" in text
    assert "bool Windows(" in text
    assert "SKATE3_PORT(82B28A00, kPortPending, kReturnR3)" in text
    assert "spec.write(ctx.r3.u32 + 8, 4);" in text


def test_deref_windows_resolve_the_pointer_first():
    text = emit.render(
        answer(windows=[{"base": "r3", "deref": [4], "offset": 336, "length": 4}]),
        0x82B28A00,
    )
    assert "spec.write(REX_LOAD_U32(ctx.r3.u32 + 4) + 336, 4);" in text


def test_nested_derefs_chain():
    expr = emit.window_expression(
        PortAnswer.model_validate(
            {"addr": "1", "code": "x;",
             "windows": [{"base": "r3", "deref": [4, 80], "offset": 0, "length": 4}]}
        ).windows[0]
    )
    assert expr == "REX_LOAD_U32(REX_LOAD_U32(ctx.r3.u32 + 4) + 80)"


def test_result_mask_names_what_the_caller_reads():
    assert "kReturnR3" in emit.render(answer(result_registers=["r3"]), 1)
    assert "kReturnF1" in emit.render(answer(result_registers=["f1"]), 1)
    assert "Vr(1)" in emit.render(answer(result_registers=["v1"]), 1)
    # Comparing nothing passes everything, so say so explicitly.
    assert "kReturnNone" in emit.render(
        answer(result_registers=[], windows=[{"base": "r3", "offset": 0, "length": 4}]), 1
    )


def test_writing_a_port_creates_the_file(tmp_path):
    artifact = emit.write(answer(), 0x82B28A00, tmp_path)
    assert artifact.path.name == "sub_82B28A00.inc"
    assert artifact.path.read_text() == artifact.text
    assert artifact.symbol == "port_82B28A00"


# --------------------------------------------------------------------- loop
@pytest.fixture
def portable(project, fixtures, tmp_path):
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


def _cassette(project, prompt_prefix: str, payload: dict, tmp_path):
    """Write a cassette keyed the way the replay provider keys calls."""
    from decomp.adapters.provider import get_provider
    from decomp.adapters.provider.base import LLMRequest
    from decomp.llm import prefix as prefix_mod
    from decomp.views import packet as packet_mod

    provider = get_provider(project, "replay")
    pkt = packet_mod.build(project, 0x82B10000)
    req = LLMRequest(prompt=pkt.text, prefix=prefix_mod.build(project).text,
                     purpose="port")
    key = provider.key(req)
    path = provider.dir / f"{key}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "ok": True, "structured": payload, "text": "",
        "usage": {"input_tokens": 400, "output_tokens": 120, "cache_read_tokens": 1800},
        "cost_usd": 0.004, "model": "replay-small",
    }))
    return path


def test_port_writes_a_file_and_records_the_ledger(portable, tmp_path):
    from decomp.pipeline.port import port_one

    _cassette(portable, "", {
        "addr": "82B10000",
        "code": "REX_STORE_U32(ctx.r3.u32 + 8, ctx.r4.u32);",
        "windows": [{"base": "r3", "offset": 8, "length": 4}],
        "result_registers": ["r3"],
        "note": "stores the argument",
    }, tmp_path)

    outcome = port_one(portable, 0x82B10000, provider_name="replay")
    assert outcome.ok, outcome.error
    assert outcome.path.is_file()
    assert portable.db.scalar("SELECT status FROM function WHERE addr=?",
                              (0x82B10000,)) == "written"
    assert portable.db.scalar("SELECT COUNT(*) FROM llm_call") == 1
    assert portable.db.scalar("SELECT COUNT(*) FROM port") == 1


def test_a_blocked_answer_is_recorded_as_a_gate(portable, tmp_path):
    from decomp.pipeline.port import port_one

    _cassette(portable, "", {
        "addr": "82B10000", "code": "// walks a list", "blocked": "gate2",
        "note": "traverses a list of unknown length, so the write set is not "
                "knowable from entry state",
    }, tmp_path)

    outcome = port_one(portable, 0x82B10000, provider_name="replay")
    assert not outcome.ok
    assert outcome.blocked == "gate2"
    row = portable.db.one("SELECT * FROM function WHERE addr=?", (0x82B10000,))
    assert row["status"] == "gate2"
    assert "unknown length" in row["gate_reason"]


def test_llm_findings_never_displace_cited_facts(portable, tmp_path):
    from decomp.pipeline.port import port_one

    portable.db.upsert("struct", {"name": "rw_command", "origin": "ingest"}, "name")
    sid = portable.db.scalar("SELECT id FROM struct WHERE name='rw_command'")
    portable.db.upsert(
        "struct_field",
        {"struct_id": sid, "offset": 4, "size": 4, "ctype": "rw_ptr",
         "name": "object", "status": "established", "confidence": 0.9},
        ("struct_id", "offset"),
    )

    _cassette(portable, "", {
        "addr": "82B10000",
        "code": "REX_STORE_U32(ctx.r3.u32 + 8, ctx.r4.u32);",
        "windows": [{"base": "r3", "offset": 8, "length": 4}],
        "result_registers": ["r3"],
        "fields": [{"struct": "rw_command", "offset": 4, "size": 4,
                    "ctype": "u32", "name": "something_else"}],
        "names": [{"addr": "82B10100", "name": "GuessedName", "confidence": 0.9}],
    }, tmp_path)

    port_one(portable, 0x82B10000, provider_name="replay")

    # The cited offset stands.
    assert portable.db.scalar(
        "SELECT name FROM struct_field WHERE struct_id=? AND offset=4", (sid,)
    ) == "object"
    # A model's name is stored as a capped-confidence proposal, not as fact.
    ev = portable.db.one(
        "SELECT * FROM symbol_evidence WHERE addr=? AND kind='llm'", (0x82B10100,)
    )
    assert ev["confidence"] <= 0.6


def test_dry_run_builds_the_packet_without_calling(portable):
    from decomp.pipeline.port import port_one

    outcome = port_one(portable, 0x82B10000, provider_name="replay", dry_run=True)
    assert not outcome.ok
    assert "dry run" in outcome.error
    assert outcome.tokens > 0
    assert portable.db.scalar("SELECT COUNT(*) FROM llm_call") == 0
