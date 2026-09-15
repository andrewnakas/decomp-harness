from __future__ import annotations

import pytest

from decomp.adapters.draft.lifted_to_native import LiftedToNative

SIMPLE = """\
DEFINE_REX_FUNC(sub_82B1D7E8) {
\tREX_FUNC_PROLOGUE();
\t// lwz r11,0(r3)
\tctx.r11.u64 = REX_LOAD_U32(ctx.r3.u32 + 0);
\t// stw r11,24(r4)
\tREX_STORE_U32(ctx.r4.u32 + 24, ctx.r11.u32);
\t// blr
\treturn;
}
"""

WITH_COMPUTE = """\
DEFINE_REX_FUNC(sub_82B20000) {
\tREX_FUNC_PROLOGUE();
\t// lwz r9,0(r3)
\tctx.r9.u64 = REX_LOAD_U32(ctx.r3.u32 + 0);
\t// rlwinm r6,r9,2,0,29
\tctx.r6.u64 = __builtin_rotateleft64(ctx.r9.u32 | (ctx.r9.u64 << 32), 2) & 0xFFFFFFFC;
\t// stw r6,8(r3)
\tREX_STORE_U32(ctx.r3.u32 + 8, ctx.r6.u32);
\treturn;
}
"""

CALLS_OUT = """\
DEFINE_REX_FUNC(sub_82B30000) {
\tREX_FUNC_PROLOGUE();
\t// bl 0x82b40000
\tctx.lr = 0x82B30008;
\tsub_82B40000(ctx, base);
\t// stw r3,0(r4)
\tREX_STORE_U32(ctx.r4.u32 + 0, ctx.r3.u32);
\treturn;
}
"""

NO_EFFECT = """\
DEFINE_REX_FUNC(sub_82B50000) {
\tREX_FUNC_PROLOGUE();
\t// lwz r9,0(r3)
\tctx.r9.u64 = REX_LOAD_U32(ctx.r3.u32 + 0);
\treturn;
}
"""


@pytest.fixture
def drafter():
    return LiftedToNative()


def test_a_simple_function_translates(drafter):
    result = drafter.draft(0x82B1D7E8, SIMPLE, {})
    assert hasattr(result, "code")
    # Registers become named locals and memory access keeps its width.
    assert "const uint32_t arg0 = ctx.r3.u32;" in result.code
    assert "REX_LOAD_U32(arg0 + 0)" in result.code
    assert "REX_STORE_U32(arg1 + 24" in result.code
    # Every line cites the instruction it came from.
    assert result.code.count("//") >= 4


def test_the_translation_is_not_a_copy(drafter):
    """A verbatim copy would pass any comparison trivially and prove nothing
    about either the port or the oracle."""
    result = drafter.draft(0x82B1D7E8, SIMPLE, {})
    assert "DEFINE_REX_FUNC" not in result.code
    assert "REX_FUNC_PROLOGUE" not in result.code
    assert "ctx.r11.u64 =" not in result.code       # the register is now a local
    assert result.code.strip() != SIMPLE.strip()


def test_windows_come_from_the_stores(drafter):
    result = drafter.draft(0x82B1D7E8, SIMPLE, {})
    assert result.windows == [
        {"base": "r4", "offset": 24, "length": 4, "why": "stw r11,24(r4)"}
    ]


def test_register_only_arithmetic_passes_through(drafter):
    """The value of this rewrite is in the memory access and the naming, not in
    re-deriving a rotate mask by hand."""
    result = drafter.draft(0x82B20000, WITH_COMPUTE, {})
    assert hasattr(result, "code")
    assert "rotateleft64" in result.code
    assert "v9" in result.code                     # operands use the named local
    assert "kept as lifted" in result.note


def test_anything_touching_memory_or_a_callee_is_refused(drafter):
    """Passing an impure expression through unexamined would be a guess."""
    result = drafter.draft(0x82B30000, CALLS_OUT, {})
    assert not hasattr(result, "code")
    assert "unrecognised" in result.reason


def test_a_function_with_nothing_observable_is_refused(drafter):
    result = drafter.draft(0x82B50000, NO_EFFECT, {})
    assert not hasattr(result, "code")
    assert "observable" in result.reason


def test_gated_and_vector_functions_are_refused(drafter):
    assert "gated" in drafter.draft(1, SIMPLE, {"gate": "gate1"}).reason
    vector = drafter.draft(1, SIMPLE, {"has_vmx": True})
    assert "vector" in vector.reason


def test_oversized_functions_are_refused(drafter):
    small = LiftedToNative(max_instructions=2)
    assert "exceeds" in small.draft(0x82B1D7E8, SIMPLE, {}).reason


def test_an_empty_body_is_refused(drafter):
    assert "no body" in drafter.draft(1, "", {}).reason


def test_sixty_four_bit_intermediates_are_preserved(drafter):
    """A truncated chain can leave memory identical and still return the wrong
    register, which surfaces only on a later call."""
    body = """\
DEFINE_REX_FUNC(sub_82B60000) {
\t// addi r9,r3,4
\tctx.r9.s64 = ctx.r3.s64 + 4;
\t// stw r9,0(r4)
\tREX_STORE_U32(ctx.r4.u32 + 0, ctx.r9.u32);
\treturn;
}
"""
    result = drafter.draft(0x82B60000, body, {})
    assert "uint64_t" in result.code


# --------------------------------------------------------------------- loop
def test_the_port_loop_tries_a_draft_before_calling_a_model(project, fixtures,
                                                            tmp_path):
    from decomp.pipeline.importer import import_lifted
    from decomp.pipeline.port import port_one

    import_lifted(project, path=fixtures / "lifted")
    project.db.execute("UPDATE function SET in_corpus=1")

    # A provider that would fail loudly if it were reached.
    project.config["providers"]["default"] = "replay"
    project.config["providers"]["replay"] = {"dir": str(tmp_path / "empty")}

    # sub_82B10300 is a load and a store: no judgment required.
    outcome = port_one(project, 0x82B10300)
    assert outcome.ok
    assert outcome.tokens == 0
    assert outcome.model == "mechanical"
    assert project.db.scalar(
        "SELECT source FROM port WHERE addr=?", (0x82B10300,)
    ) == "mechanical"


def test_drafting_can_be_turned_off(project, fixtures, tmp_path):
    from decomp.pipeline.importer import import_lifted
    from decomp.pipeline.port import port_one

    import_lifted(project, path=fixtures / "lifted")
    project.db.execute("UPDATE function SET in_corpus=1")
    project.config["providers"]["default"] = "replay"
    project.config["providers"]["replay"] = {"dir": str(tmp_path / "empty")}

    outcome = port_one(project, 0x82B10300, allow_draft=False)
    assert not outcome.ok          # no cassette, so the provider call fails
    assert "no cassette" in outcome.error
