"""SQLite access: connection, migrations, typed helpers.

The database is the harness's memory. Every fact the model would otherwise have
to rediscover lives here with provenance.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def _dict_factory(cursor: sqlite3.Cursor, row: tuple) -> dict[str, Any]:
    return {col[0]: row[i] for i, col in enumerate(cursor.description)}


class Db:
    """Thin wrapper over sqlite3 with migrations and a few typed conveniences."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, isolation_level=None)
        self.conn.row_factory = _dict_factory
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.migrate()

    # ------------------------------------------------------------ migrations
    def user_version(self) -> int:
        return int(self.conn.execute("PRAGMA user_version").fetchone()["user_version"])

    def migrate(self) -> int:
        """Apply any migration files whose numeric prefix exceeds user_version."""
        applied = 0
        current = self.user_version()
        files = sorted(MIGRATIONS_DIR.glob("*.sql"))
        for f in files:
            version = int(f.name.split("_", 1)[0])
            if version <= current:
                continue
            self.conn.executescript(f.read_text())
            self.conn.execute(f"PRAGMA user_version={version}")
            applied += 1
            current = version
        return applied

    # ------------------------------------------------------------- basic ops
    def execute(self, sql: str, params: Sequence | Mapping = ()) -> sqlite3.Cursor:
        return self.conn.execute(sql, params)

    def executemany(self, sql: str, rows: Iterable[Sequence | Mapping]) -> sqlite3.Cursor:
        return self.conn.executemany(sql, rows)

    def query(self, sql: str, params: Sequence | Mapping = ()) -> list[dict[str, Any]]:
        return self.conn.execute(sql, params).fetchall()

    def one(self, sql: str, params: Sequence | Mapping = ()) -> dict[str, Any] | None:
        return self.conn.execute(sql, params).fetchone()

    def scalar(self, sql: str, params: Sequence | Mapping = (), default: Any = None) -> Any:
        row = self.one(sql, params)
        if row is None:
            return default
        return next(iter(row.values()))

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """Explicit transaction (isolation_level=None means autocommit otherwise)."""
        self.conn.execute("BEGIN")
        try:
            yield self.conn
        except Exception:
            self.conn.execute("ROLLBACK")
            raise
        else:
            self.conn.execute("COMMIT")

    # --------------------------------------------------------------- upserts
    def upsert(self, table: str, row: Mapping[str, Any], key: str | Sequence[str]) -> None:
        keys = [key] if isinstance(key, str) else list(key)
        cols = list(row.keys())
        placeholders = ", ".join("?" for _ in cols)
        updates = ", ".join(f"{c}=excluded.{c}" for c in cols if c not in keys)
        conflict = ", ".join(keys)
        sql = f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({placeholders})"
        if updates:
            sql += f" ON CONFLICT({conflict}) DO UPDATE SET {updates}"
        else:
            sql += f" ON CONFLICT({conflict}) DO NOTHING"
        self.conn.execute(sql, [row[c] for c in cols])

    def meta_get(self, key: str, default: Any = None) -> Any:
        return self.scalar("SELECT value FROM meta WHERE key=?", (key,), default)

    def meta_set(self, key: str, value: Any) -> None:
        self.upsert("meta", {"key": key, "value": str(value)}, "key")

    def close(self) -> None:
        self.conn.close()


def addr_str(addr: int) -> str:
    """Canonical rendering of a guest address."""
    return f"sub_{addr:08X}"


def parse_addr(text: str) -> int:
    """Accept 82B28A00, 0x82B28A00, sub_82B28A00."""
    t = text.strip().lower()
    if t.startswith("sub_"):
        t = t[4:]
    if t.startswith("0x"):
        t = t[2:]
    return int(t, 16)
