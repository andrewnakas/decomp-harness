-- An indirect call has no known target, but a WITHOUT ROWID primary key cannot
-- hold NULL. Address 0 is never a valid guest function, so it is the sentinel
-- for "no known target" (indirect calls and unresolved branches).

ALTER TABLE xref RENAME TO xref_old;

CREATE TABLE xref (
    caller      INTEGER NOT NULL,
    callee      INTEGER NOT NULL DEFAULT 0,   -- 0 = no known target
    callee_name TEXT NOT NULL DEFAULT '',
    kind        TEXT NOT NULL,                -- direct|indirect|import|helper|unresolved
    site_line   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (caller, callee, callee_name, site_line)
) WITHOUT ROWID;

INSERT OR IGNORE INTO xref (caller, callee, callee_name, kind, site_line)
SELECT caller, COALESCE(callee, 0), COALESCE(callee_name, ''), kind,
       COALESCE(site_line, 0)
FROM xref_old;

DROP TABLE xref_old;

CREATE INDEX IF NOT EXISTS ix_xref_callee ON xref(callee);
CREATE INDEX IF NOT EXISTS ix_xref_kind ON xref(kind);
