from __future__ import annotations

import pytest

from decomp.views.cnorm import (
    has_unresolved_branch,
    is_usable,
    normalize,
    signature_of,
)

GHIDRA_C = """
undefined8 rwaudio_OnEventPlay(int param_1)

{
  float fVar1;
  int iVar2;
  undefined4 *puVar3;
  bool bVar4;

  iVar2 = *(int *)(param_1 + 4);
  *(undefined4 *)(iVar2 + 0x150) = 0;
  *(undefined1 *)(iVar2 + 0x160) = (undefined1)(longlong)fVar1;
  return 0x14;
}
"""

FAILED = """
void FUN_82af0338(void)

{
  halt_baddata();
}
"""

BRANCHY = """
void FUN_82b10000(void)

{
  (*(code *)&code_r0x82b10040)();
  return;
}
"""


def test_placeholder_types_become_widths():
    view = normalize(GHIDRA_C)
    assert "undefined4" not in view.text
    assert "u32" in view.text and "u64" in view.text
    assert "i64" in view.text          # longlong


def test_declaration_block_is_dropped():
    view = normalize(GHIDRA_C)
    assert view.dropped_decls == 4
    assert "float fVar1;" not in view.text
    # The variables are still used, and their use says more than their type did.
    assert "fVar1" in view.text


def test_offsets_are_annotated_not_rewritten():
    """Rewriting the expression would state a fact the harness has not
    established: which struct that pointer points to."""
    view = normalize(GHIDRA_C, {0x150: "Player.decoder", 0x160: "Player.format_index"})
    assert "(iVar2 + 0x150)" in view.text      # expression untouched
    assert "// Player.decoder" in view.text    # meaning added alongside
    assert 0x150 in view.offsets_seen


def test_unknown_offsets_get_no_annotation():
    view = normalize(GHIDRA_C, {0x999: "Nope.field"})
    assert "//" not in view.text


def test_only_halt_baddata_means_the_decompiler_gave_up():
    assert is_usable(GHIDRA_C)
    assert not is_usable(FAILED)
    # An unnamed branch target is still real code. Treating it as a failure
    # would push 186 of the audio corpus's 1,694 functions onto the expensive
    # path for no reason.
    assert is_usable(BRANCHY)
    assert has_unresolved_branch(BRANCHY)
    assert not has_unresolved_branch(GHIDRA_C)


def test_empty_source_is_not_usable():
    assert not is_usable("")
    assert not is_usable("   \n  ")


def test_signature_is_recovered():
    assert signature_of(GHIDRA_C) == "undefined8 rwaudio_OnEventPlay(int param_1)"
    assert signature_of("") == ""


def test_reduction_is_reported_honestly():
    view = normalize(GHIDRA_C)
    assert view.original_chars == len(GHIDRA_C)
    assert view.chars == len(view.text)
    assert 0.0 < view.reduction < 1.0
    assert "smaller" in view.brief()


# ------------------------------------------------------------------ packets
@pytest.fixture
def packed(project, fixtures, tmp_path):
    from decomp.pipeline.importer import (
        import_decompiled,
        import_lifted,
        import_structs,
        import_xrefs,
    )
    from decomp.pipeline.queue import build as queue_build
    from decomp.pipeline.screen import screen

    import_lifted(project, path=fixtures / "lifted")
    import_structs(project, path=fixtures / "ingest/structs.h")
    project.db.execute("UPDATE function SET in_corpus=1 WHERE addr < 0x82F00000")
    import_xrefs(project, scope="corpus")

    decomp_dir = tmp_path / "decomp"
    decomp_dir.mkdir()
    (decomp_dir / "sub_82B10000.c").write_text(GHIDRA_C)
    (decomp_dir / "sub_82B10100.c").write_text(FAILED)
    import_decompiled(project, path=decomp_dir)

    screen(project)
    queue_build(project)
    return project


def test_packet_is_self_contained_and_small(packed):
    from decomp.views.packet import build

    pk = build(packed, 0x82B10000)
    assert pk.tokens < 1200
    # The model has no file tools, so a packet must never point at one.
    assert "/" not in pk.text.split("--- ")[0].replace("//", "")
    assert "read the file" not in pk.text.lower()
    assert pk.text.startswith("# sub_82B10000")
    assert "callees:" in pk.text


def test_vector_functions_get_assembly_not_c(packed):
    """Lane order is the thing being ported, and scalar C hides it."""
    from decomp.views.packet import build

    pk = build(packed, 0x82B10100)
    assert pk.form == "asm"
    assert "lvx128" in pk.text


def test_a_failed_decompile_falls_back_to_assembly(packed):
    from decomp.views.packet import build

    packed.db.upsert("function", {"addr": 0x82B10100, "vmx128": 0}, "addr")
    pk = build(packed, 0x82B10100)
    assert pk.form == "asm"
    assert "halt_baddata" not in pk.text


def test_resolved_callees_appear_by_name(packed):
    from decomp.views.packet import build

    text = build(packed, 0x82B10000).text
    assert "sub_82B10100" in text
    # Frame bookkeeping is not a callee worth naming.
    assert "__savegprlr" not in text


def test_a_ported_callee_is_flagged(packed):
    from decomp.views.packet import build

    packed.db.upsert("function", {"addr": 0x82B10100, "status": "verified"}, "addr")
    assert "[ported]" in build(packed, 0x82B10000).text


def test_divergence_is_appended_on_retry(packed):
    from decomp.views.packet import build

    pk = build(packed, 0x82B10000,
               divergence="run 1 diverges in memory at 40C219DC+0 (lifted 01, native 00)",
               attempt=2)
    assert "attempt=2" in pk.text
    assert "40C219DC" in pk.text
    assert pk.sections["divergence"] > 0


def test_unknown_function_is_an_error(packed):
    from decomp.views.packet import build

    with pytest.raises(KeyError, match="not in this project"):
        build(packed, 0xDEADBEEF)


def test_oversized_packets_drop_a_section_rather_than_being_sent(packed):
    from decomp.views.packet import PacketBudget, build

    tiny = PacketBudget(target_tokens=10, max_tokens=40)
    pk = build(packed, 0x82B10000, budget=tiny, form="both")
    assert pk.dropped, "an over-budget packet must say what it gave up"
