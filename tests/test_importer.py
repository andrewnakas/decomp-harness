from __future__ import annotations

from decomp.pipeline.importer import (
    import_lifted,
    import_names,
    import_notes,
    import_queue,
    import_structs,
    import_trace,
    import_xrefs,
)


# ------------------------------------------------------------------ lifted
def test_import_lifted_populates_functions_and_symbols(project, fixtures):
    res = import_lifted(project, path=fixtures / "lifted")
    assert res.counts["functions"] == 3

    row = project.db.one("SELECT * FROM function WHERE addr=?", (0x82B10100,))
    assert row["vmx128"] == 1
    assert row["tu"] == "tiny_recomp.0.cpp"
    assert row["lifted_lines"] > 5

    # Helpers and imports are known by name from their call sites, and that is
    # stronger evidence than anything a model would offer.
    helper = project.db.one("SELECT * FROM function WHERE addr=?", (0x82F52114,))
    assert helper["name"] == "__savegprlr_27" and helper["is_helper"] == 1
    imp = project.db.one("SELECT * FROM function WHERE addr=?", (0x82F60000,))
    assert imp["is_import"] == 1

    ev = project.db.one(
        "SELECT * FROM symbol_evidence WHERE addr=? AND kind='lifted'", (0x82F60000,)
    )
    assert ev["confidence"] >= 0.9


def test_import_lifted_is_idempotent(project, fixtures):
    from decomp.core.stages import StageSkipped

    import_lifted(project, path=fixtures / "lifted")
    again = import_lifted(project, path=fixtures / "lifted")
    assert isinstance(again, StageSkipped)
    assert project.db.scalar("SELECT COUNT(*) FROM function") == 5  # 3 + helper + import


def test_import_xrefs_records_edges_and_constants(project, fixtures):
    import_lifted(project, path=fixtures / "lifted")
    project.db.execute("UPDATE function SET in_corpus=1")
    res = import_xrefs(project, scope="corpus")
    assert res.counts["edges"] > 0

    kinds = {
        r["kind"]
        for r in project.db.query("SELECT kind FROM xref WHERE caller=?", (0x82B10100,))
    }
    assert "import" in kinds
    assert project.db.scalar(
        "SELECT COUNT(*) FROM xref WHERE caller=? AND kind='indirect'", (0x82B10200,)
    ) == 1
    assert project.db.scalar(
        "SELECT COUNT(*) FROM const_ref WHERE addr=? AND value=?",
        (0x82B10200, 0x820149B4),
    ) == 1


# ------------------------------------------------------------------- names
def test_import_names_csv_and_toml(project, fixtures):
    res = import_names(project, path=fixtures / "ingest/names.csv")
    assert res.counts["names"] == 3          # the malformed line is skipped
    assert project.db.scalar(
        "SELECT name FROM function WHERE addr=?", (0x82B28A00,)
    ) == "rwaudio_PacketPlayer_QueueCommand"

    res2 = import_names(project, path=fixtures / "ingest/names.toml")
    assert res2.counts["names"] == 2
    assert project.db.scalar("SELECT name FROM function WHERE addr=?", (0x82B20070,))


def test_names_keep_their_provenance(project, fixtures):
    import_names(project, path=fixtures / "ingest/names.csv", kind="plugin_meta",
                 confidence=0.85)
    ev = project.db.one("SELECT * FROM symbol_evidence WHERE addr=?", (0x82B28A00,))
    assert ev["kind"] == "plugin_meta"
    assert ev["source"] == "names.csv"
    assert ev["confidence"] == 0.85


# ----------------------------------------------------------------- structs
def test_import_structs_recovers_offsets_and_citations(project, fixtures):
    res = import_structs(project, path=fixtures / "ingest/structs.h")
    assert res.counts["structs"] == 2

    fields = {
        r["name"]: r
        for r in project.db.query(
            "SELECT f.* FROM struct_field f JOIN struct s ON s.id=f.struct_id "
            "WHERE s.name='rw_scheduler'"
        )
    }
    # Padding is consumed for layout but never becomes a field.
    assert set(fields) == {"buckets", "delta_time", "current_node", "node_removed"}
    assert fields["buckets"]["offset"] == 0x10
    assert fields["buckets"]["size"] == 8          # rw_ptr[2]
    assert fields["delta_time"]["offset"] == 0x40
    assert fields["node_removed"]["offset"] == 0x4C
    assert project.db.scalar("SELECT size FROM struct WHERE name='rw_scheduler'") == 0x50

    # The function named above the struct is recorded as the offset's source.
    cited = project.db.query(
        "SELECT fe.function_addr FROM field_evidence fe JOIN struct_field f "
        "ON f.id=fe.field_id JOIN struct s ON s.id=f.struct_id WHERE s.name='rw_scheduler'"
    )
    assert {r["function_addr"] for r in cited} == {0x82B48A50}


def test_struct_import_handles_multiple_citations(project, fixtures):
    import_structs(project, path=fixtures / "ingest/structs.h")
    cited = {
        r["function_addr"]
        for r in project.db.query(
            "SELECT fe.function_addr FROM field_evidence fe JOIN struct_field f "
            "ON f.id=fe.field_id JOIN struct s ON s.id=f.struct_id WHERE s.name='rw_command'"
        )
    }
    assert cited == {0x82B28A00, 0x82B48530}


# ------------------------------------------------------------------ traces
def test_import_trace_counts_calls_and_attributes_threads(project, fixtures):
    res = import_trace(project, path=fixtures / "ingest/trace.tsv", profile="play")
    assert res.counts["functions"] == 3
    assert res.counts["calls"] == 4

    row = project.db.one("SELECT * FROM function WHERE addr=?", (0x82B28A00,))
    assert row["calls_play"] == 2
    assert row["thread_first"] == "RwAudioCore Dac"
    assert row["hot"] == 2
    assert project.db.scalar(
        "SELECT thread FROM trace_call WHERE addr=?", (0x82B10000,)
    ) == "main"


def test_trace_accepts_a_bare_address_list(project, tmp_path):
    listing = tmp_path / "addrs.txt"
    listing.write_text("82B00040\n82B000E8\n\n# comment\n")
    res = import_trace(project, path=listing, profile="boot")
    assert res.counts["functions"] == 2
    assert project.db.scalar("SELECT calls_boot FROM function WHERE addr=?", (0x82B00040,)) == 1


# ------------------------------------------------------------------- queue
def test_import_queue_restores_prior_verdicts(project, fixtures):
    res = import_queue(project, path=fixtures / "ingest/queue.json")
    assert res.counts["functions"] == 2

    verified = project.db.one("SELECT * FROM function WHERE addr=?", (0x82B28A00,))
    assert verified["status"] == "verified"
    assert verified["tier"] == "A"
    assert verified["calls_play"] == 6706
    assert "producer" in verified["note"]

    gated = project.db.one("SELECT * FROM function WHERE addr=?", (0x82B3C930,))
    assert gated["gate"] == "gate1"
    assert gated["gate_reason"] == "indirect call"


# ------------------------------------------------------------------- notes
def test_import_notes_trims_to_packet_size(project, fixtures):
    res = import_notes(project, path=fixtures / "ingest/notes")
    assert res.counts["notes"] == 1
    note = project.db.scalar("SELECT note FROM function WHERE addr=?", (0x82B28A00,))
    assert len(note) <= 300
    assert "command queue entry" in note
    assert "should not be summarized" not in note   # the code fence ends the summary
