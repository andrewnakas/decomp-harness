from __future__ import annotations

from decomp.core.db import Db, addr_str, parse_addr


def test_migrations_apply_and_are_idempotent(tmp_path):
    db = Db(tmp_path / "t.sqlite")
    assert db.user_version() >= 1
    assert db.migrate() == 0  # second call applies nothing

    tables = {
        r["name"]
        for r in db.query("SELECT name FROM sqlite_master WHERE type='table'")
    }
    for expected in ("function", "xref", "llm_call", "lesson", "verdict", "struct_field"):
        assert expected in tables


def test_upsert_replaces_on_conflict(tmp_path):
    db = Db(tmp_path / "t.sqlite")
    db.upsert("function", {"addr": 0x82B28A00, "name": "first"}, "addr")
    db.upsert("function", {"addr": 0x82B28A00, "name": "second"}, "addr")
    assert db.scalar("SELECT COUNT(*) FROM function") == 1
    assert db.scalar("SELECT name FROM function") == "second"


def test_meta_roundtrip(tmp_path):
    db = Db(tmp_path / "t.sqlite")
    assert db.meta_get("missing", "fallback") == "fallback"
    db.meta_set("k", 42)
    assert db.meta_get("k") == "42"


def test_transaction_rolls_back(tmp_path):
    db = Db(tmp_path / "t.sqlite")
    try:
        with db.tx():
            db.execute("INSERT INTO function (addr, name) VALUES (1, 'x')")
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    assert db.scalar("SELECT COUNT(*) FROM function") == 0


def test_address_formatting():
    assert addr_str(0x82B28A00) == "sub_82B28A00"
    for text in ("82B28A00", "0x82b28a00", "sub_82B28A00", " sub_82b28a00 "):
        assert parse_addr(text) == 0x82B28A00
