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


def test_the_database_is_usable_from_another_thread(tmp_path):
    """MCP serves tools on a worker thread, and a connection bound to its
    creating thread throws there."""
    import threading

    db = Db(tmp_path / "t.sqlite")
    errors: list[Exception] = []

    def writer(n: int) -> None:
        try:
            db.upsert("function", {"addr": n, "name": f"fn{n}"}, "addr")
            db.query("SELECT * FROM function WHERE addr=?", (n,))
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(1, 25)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors[0]
    assert db.scalar("SELECT COUNT(*) FROM function") == 24


def test_concurrent_transactions_do_not_interleave(tmp_path):
    """A second writer landing between BEGIN and COMMIT would be inside someone
    else's unit of work."""
    import threading

    db = Db(tmp_path / "t.sqlite")
    errors: list[Exception] = []

    def batch(base: int) -> None:
        try:
            with db.tx():
                for i in range(20):
                    db.execute(
                        "INSERT INTO function (addr, name) VALUES (?,?)",
                        (base + i, f"fn{base + i}"),
                    )
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=batch, args=(b,)) for b in (100, 200, 300)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors[0]
    assert db.scalar("SELECT COUNT(*) FROM function") == 60
