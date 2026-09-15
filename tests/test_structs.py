from __future__ import annotations

import shutil
import subprocess

import pytest

from decomp.pipeline.structs import check, export


@pytest.fixture
def layouts(project, fixtures):
    from decomp.pipeline.importer import import_structs

    import_structs(project, path=fixtures / "ingest/structs.h")
    return project


def test_export_round_trips_the_offsets(layouts, tmp_path):
    result = export(layouts, out_dir=tmp_path)
    assert result.structs == 2
    assert result.header_path.is_file()
    assert result.check_path.is_file()

    header = result.header_path.read_text()
    assert "typedef struct {" in header
    assert "buckets[2]" in header          # the array dimension survives
    assert "/* +0x040" in header           # delta_time
    # Padding is reconstructed from the offsets, not stored.
    assert "_pad00[0x10]" in header


def test_the_citation_travels_with_the_layout(layouts, tmp_path):
    header = export(layouts, out_dir=tmp_path).header_path.read_text()
    assert "Read from sub_82B48A50" in header
    assert "sub_82B28A00" in header        # rw_command's two citations


def test_assertions_are_generated_for_established_fields(layouts, tmp_path):
    checks = export(layouts, out_dir=tmp_path).check_path.read_text()
    assert "CHECK(rw_scheduler, delta_time, 0x40);" in checks
    assert "CHECK(rw_scheduler, node_removed, 0x4C);" in checks


def test_a_proposal_is_emitted_but_never_asserted(layouts, tmp_path):
    """A static assertion on a guess would fail the build for the wrong reason."""
    struct_id = layouts.db.scalar("SELECT id FROM struct WHERE name='rw_command'")
    layouts.db.upsert(
        "struct_field",
        {"struct_id": struct_id, "offset": 8, "size": 4, "ctype": "uint32_t",
         "name": "guessed", "status": "proposed"},
        ("struct_id", "offset"),
    )
    result = export(layouts, out_dir=tmp_path)
    assert result.proposed == 1
    assert "guessed" in result.header_path.read_text()
    assert "(proposed)" in result.header_path.read_text()
    assert "guessed" not in result.check_path.read_text()
    assert "not asserted" in result.brief()


def test_proposals_can_be_left_out_entirely(layouts, tmp_path):
    struct_id = layouts.db.scalar("SELECT id FROM struct WHERE name='rw_command'")
    layouts.db.upsert(
        "struct_field",
        {"struct_id": struct_id, "offset": 8, "size": 4, "ctype": "uint32_t",
         "name": "guessed", "status": "proposed"},
        ("struct_id", "offset"),
    )
    result = export(layouts, out_dir=tmp_path, include_proposed=False)
    assert "guessed" not in result.header_path.read_text()


def test_a_nested_struct_takes_the_space_it_actually_occupies(project, tmp_path):
    """Offsets are measured; sizes are inferred. Trusting an inferred size to
    fill a gap shifted every field after a nested struct by twelve bytes."""
    project.db.upsert("struct", {"name": "inner", "size": 0x50}, "name")
    inner = project.db.scalar("SELECT id FROM struct WHERE name='inner'")
    project.db.upsert(
        "struct_field",
        {"struct_id": inner, "offset": 0, "size": 4, "ctype": "uint32_t",
         "name": "first", "status": "established"},
        ("struct_id", "offset"),
    )
    project.db.upsert("struct", {"name": "outer", "size": 0x80}, "name")
    outer = project.db.scalar("SELECT id FROM struct WHERE name='outer'")
    # The importer had no way to know inner's size when it parsed outer.
    project.db.upsert(
        "struct_field",
        {"struct_id": outer, "offset": 0x10, "size": 4, "ctype": "inner",
         "name": "nested", "status": "established"},
        ("struct_id", "offset"),
    )
    project.db.upsert(
        "struct_field",
        {"struct_id": outer, "offset": 0x70, "size": 4, "ctype": "uint32_t",
         "name": "after", "status": "established"},
        ("struct_id", "offset"),
    )
    header = export(project, out_dir=tmp_path).header_path.read_text()
    assert "inner        nested;" in header
    # inner occupies 0x10..0x60, so the gap to `after` must be named.
    assert "_gap60[0x10]" in header


def test_an_unknown_type_reserves_its_measured_space(project, tmp_path):
    """Emitting a type of unknown width lets the compiler pick its size and
    shifts everything after it."""
    project.db.upsert("struct", {"name": "s", "size": 0x20}, "name")
    sid = project.db.scalar("SELECT id FROM struct WHERE name='s'")
    project.db.upsert(
        "struct_field",
        {"struct_id": sid, "offset": 0, "size": 4, "ctype": "mystery_t",
         "name": "thing", "status": "established"},
        ("struct_id", "offset"),
    )
    project.db.upsert(
        "struct_field",
        {"struct_id": sid, "offset": 0x10, "size": 4, "ctype": "uint32_t",
         "name": "after", "status": "established"},
        ("struct_id", "offset"),
    )
    header = export(project, out_dir=tmp_path).header_path.read_text()
    assert "thing[0x10]" in header
    assert "mystery_t" in header       # the real type is still recorded


def test_a_size_alignment_cannot_hold_is_not_asserted(project, tmp_path):
    """A recovered size is the end of the last field, and a struct ending on an
    odd byte gets padded, so asserting it would fail for the wrong reason."""
    project.db.upsert("struct", {"name": "odd", "size": 0x161}, "name")
    sid = project.db.scalar("SELECT id FROM struct WHERE name='odd'")
    project.db.upsert(
        "struct_field",
        {"struct_id": sid, "offset": 0, "size": 4, "ctype": "uint32_t",
         "name": "word", "status": "established"},
        ("struct_id", "offset"),
    )
    checks = export(project, out_dir=tmp_path).check_path.read_text()
    assert "sizeof(odd)" not in checks
    assert "not asserted" in checks


@pytest.mark.skipif(shutil.which("cc") is None, reason="needs a C compiler")
def test_the_generated_assertions_actually_compile(layouts, tmp_path):
    """The point of the assertions is that a wrong layout fails here."""
    result = export(layouts, out_dir=tmp_path)
    proc = subprocess.run(
        ["cc", "-fsyntax-only", "-I", str(tmp_path), str(result.check_path)],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr[:2000]


# --------------------------------------------------------------------- check
def test_consistent_layouts_report_clean(layouts):
    result = check(layouts)
    assert result.ok
    assert "consistent" in result.brief()


def test_an_overlap_is_reported(project):
    project.db.upsert("struct", {"name": "s", "size": 0x20}, "name")
    sid = project.db.scalar("SELECT id FROM struct WHERE name='s'")
    for offset, size, name in ((0, 8, "wide"), (4, 4, "inside")):
        project.db.upsert(
            "struct_field",
            {"struct_id": sid, "offset": offset, "size": size,
             "ctype": "uint32_t", "name": name, "status": "established"},
            ("struct_id", "offset"),
        )
    result = check(project)
    assert not result.ok
    assert result.overlaps
    assert "overlap" in result.brief()


def test_a_field_with_no_evidence_is_flagged(project):
    project.db.upsert("struct", {"name": "s", "size": 4}, "name")
    sid = project.db.scalar("SELECT id FROM struct WHERE name='s'")
    project.db.upsert(
        "struct_field",
        {"struct_id": sid, "offset": 0, "size": 4, "ctype": "uint32_t",
         "name": "bare", "status": "proposed"},
        ("struct_id", "offset"),
    )
    result = check(project)
    assert result.unevidenced
    assert "unevidenced" in result.brief()
