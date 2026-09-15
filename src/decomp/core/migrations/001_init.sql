-- DecompHarness schema v1
-- All addresses are INTEGER (rendered as sub_%08X on output).

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS target (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL,
    platform        TEXT,              -- xbox360 | ps3 | n64 | generic
    arch            TEXT,              -- ppc64 | mips | x86 ...
    endian          TEXT,              -- big | little
    ptr_size        INTEGER DEFAULT 4,
    base_addr       INTEGER,
    image_path      TEXT,
    image_sha256    TEXT,
    ghidra_project  TEXT,
    ghidra_lang     TEXT,
    recomp_path     TEXT,
    adapter         TEXT,              -- target adapter id
    config_json     TEXT
);

-- ---------------------------------------------------------------- functions
CREATE TABLE IF NOT EXISTS function (
    addr                INTEGER PRIMARY KEY,
    size                INTEGER,
    name                TEXT,
    name_confidence     REAL DEFAULT 0.0,
    tu                  TEXT,           -- lifted translation unit (skate3_recomp.67.cpp)
    tu_line             INTEGER,
    lifted_lines        INTEGER,
    ghidra_lines        INTEGER,
    vmx128              INTEGER DEFAULT 0,
    is_import           INTEGER DEFAULT 0,
    is_helper           INTEGER DEFAULT 0,
    is_leaf             INTEGER,
    subsystem_id        INTEGER,
    in_corpus           INTEGER DEFAULT 0,
    corpus_depth        INTEGER,
    tier                TEXT,           -- A B C D E F L U
    status              TEXT DEFAULT 'pending',
    gate                TEXT,           -- gate1..gate4 or NULL
    gate_reason         TEXT,
    difficulty          REAL,
    family_id           INTEGER,
    attempts            INTEGER DEFAULT 0,
    calls_boot          INTEGER,
    calls_play          INTEGER,
    calls_map           INTEGER,
    hot                 INTEGER,        -- max(calls_*)
    thread_first        TEXT,
    thread_dom          TEXT,
    signature           TEXT,
    note                TEXT,
    last_divergence     TEXT,
    updated_at          TEXT
);
CREATE INDEX IF NOT EXISTS ix_function_status    ON function(status);
CREATE INDEX IF NOT EXISTS ix_function_subsystem ON function(subsystem_id);
CREATE INDEX IF NOT EXISTS ix_function_tier_hot  ON function(tier, hot DESC);
CREATE INDEX IF NOT EXISTS ix_function_corpus    ON function(in_corpus);

CREATE TABLE IF NOT EXISTS xref (
    caller    INTEGER NOT NULL,
    callee    INTEGER,
    callee_name TEXT,
    kind      TEXT NOT NULL,       -- direct | indirect | import | helper | unresolved
    site_line INTEGER,
    PRIMARY KEY (caller, callee, callee_name, site_line)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ix_xref_callee ON xref(callee);

CREATE TABLE IF NOT EXISTS const_ref (
    addr           INTEGER NOT NULL,
    value          INTEGER NOT NULL,
    kind           TEXT,            -- string | data | code | unknown
    string_preview TEXT,
    PRIMARY KEY (addr, value)
) WITHOUT ROWID;

-- ---------------------------------------------------------------- knowledge
CREATE TABLE IF NOT EXISTS symbol_evidence (
    id          INTEGER PRIMARY KEY,
    addr        INTEGER NOT NULL,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL,     -- plugin_meta|rtti|string|import|lifted|bsim|fid|llm|user|ingest
    source      TEXT,
    confidence  REAL DEFAULT 0.5,
    run_id      INTEGER,
    created_at  TEXT
);
CREATE INDEX IF NOT EXISTS ix_symev_addr ON symbol_evidence(addr);

CREATE TABLE IF NOT EXISTS struct (
    id     INTEGER PRIMARY KEY,
    name   TEXT UNIQUE NOT NULL,
    size   INTEGER,
    origin TEXT                    -- ingest | harvest | llm | user
);

CREATE TABLE IF NOT EXISTS struct_field (
    id         INTEGER PRIMARY KEY,
    struct_id  INTEGER NOT NULL,
    offset     INTEGER NOT NULL,
    size       INTEGER,
    ctype      TEXT,
    name       TEXT,
    status     TEXT DEFAULT 'proposed',   -- proposed|established|confirmed|conflict
    confidence REAL DEFAULT 0.5,
    UNIQUE (struct_id, offset)
);

CREATE TABLE IF NOT EXISTS field_evidence (
    id           INTEGER PRIMARY KEY,
    field_id     INTEGER NOT NULL,
    function_addr INTEGER,
    access       TEXT,             -- load | store
    kind         TEXT,             -- static:ghidra|static:lifted|runtime:probe|doc|llm|user
    locator      TEXT,             -- "sub_82B28A00:L37"
    snippet      TEXT,
    confidence   REAL DEFAULT 0.5,
    created_at   TEXT
);
CREATE INDEX IF NOT EXISTS ix_fieldev_field ON field_evidence(field_id);

-- raw harvest, before any struct assignment
CREATE TABLE IF NOT EXISTS field_access (
    id            INTEGER PRIMARY KEY,
    function_addr INTEGER NOT NULL,
    base_kind     TEXT,            -- param | derived | global | stack
    base_ref      TEXT,            -- "r3" | "field:<id>" | "0x82165A10"
    offset        INTEGER,
    size          INTEGER,
    access        TEXT,
    line          INTEGER
);
CREATE INDEX IF NOT EXISTS ix_fieldacc_fn ON field_access(function_addr);

-- ---------------------------------------------------------------- pipeline
CREATE TABLE IF NOT EXISTS subsystem (
    id         INTEGER PRIMARY KEY,
    name       TEXT UNIQUE,
    seeds_json TEXT,
    score_json TEXT,
    size       INTEGER,
    chosen     INTEGER DEFAULT 0,
    notes      TEXT
);

CREATE TABLE IF NOT EXISTS gate (
    addr            INTEGER PRIMARY KEY,
    gate            TEXT,          -- pass | gate1 | gate2 | gate3 | gate4
    reasons_json    TEXT,
    store_prov_json TEXT,
    windows_json    TEXT,
    rules_version   TEXT,
    screened_at     TEXT
);

CREATE TABLE IF NOT EXISTS port (
    addr        INTEGER PRIMARY KEY,
    path        TEXT,
    status      TEXT,              -- pending|written|armed|verified|thin|partial|promoted|divergent
    result_mask TEXT,
    windows_json TEXT,
    lint_ok     INTEGER,
    lint_json   TEXT,
    build_id    INTEGER,
    answer_id   INTEGER,
    source      TEXT,              -- mechanical | m2c | llm | human
    updated_at  TEXT
);

CREATE TABLE IF NOT EXISTS build (
    id             INTEGER PRIMARY KEY,
    host           TEXT,
    ports_hash     TEXT,
    artifact_path  TEXT,
    artifact_sha   TEXT,
    artifact_mtime REAL,
    nm_symbols_ok  INTEGER,
    expected_syms  INTEGER,
    found_syms     INTEGER,
    ok             INTEGER,
    duration_s     REAL,
    log_path       TEXT,
    created_at     TEXT
);

CREATE TABLE IF NOT EXISTS session (
    id                  INTEGER PRIMARY KEY,
    host                TEXT,
    build_id            INTEGER,
    profile             TEXT,          -- boot | play | map
    armed_json          TEXT,
    negative_controls_json TEXT,
    negcontrol_ok       INTEGER DEFAULT 0,
    trusted             INTEGER DEFAULT 0,
    calls_total         INTEGER,
    summary_json        TEXT,
    log_path            TEXT,
    started             TEXT,
    ended               TEXT
);

CREATE TABLE IF NOT EXISTS verdict (
    id         INTEGER PRIMARY KEY,
    session_id INTEGER NOT NULL,
    addr       INTEGER NOT NULL,
    result     TEXT,                   -- verified|diverged|uncalled|census|overflow|skipped
    calls      INTEGER,
    compared   INTEGER,
    skipped    INTEGER,
    first_divergence_json TEXT
);
CREATE INDEX IF NOT EXISTS ix_verdict_addr ON verdict(addr);

CREATE TABLE IF NOT EXISTS trace_call (
    profile   TEXT NOT NULL,
    addr      INTEGER NOT NULL,
    thread    TEXT,
    count     INTEGER,
    first_seq INTEGER,
    PRIMARY KEY (profile, addr)
) WITHOUT ROWID;

-- ---------------------------------------------------------------- llm ledger
CREATE TABLE IF NOT EXISTS llm_call (
    id                 INTEGER PRIMARY KEY,
    ts                 TEXT,
    run_id             INTEGER,
    provider           TEXT,
    model              TEXT,
    purpose            TEXT,           -- port|retry|name|triage|batch|ping
    addrs_json         TEXT,
    packet_hash        TEXT,
    packet_tokens_est  INTEGER,
    prefix_hash        TEXT,
    input_tokens       INTEGER DEFAULT 0,
    cache_read_tokens  INTEGER DEFAULT 0,
    cache_write_tokens INTEGER DEFAULT 0,
    output_tokens      INTEGER DEFAULT 0,
    cost_usd           REAL,
    session_ref        TEXT,
    resumed            INTEGER DEFAULT 0,
    attempt            INTEGER DEFAULT 1,
    duration_ms        INTEGER,
    schema_ok          INTEGER,
    outcome            TEXT,
    error              TEXT,
    answer_path        TEXT
);
CREATE INDEX IF NOT EXISTS ix_llmcall_ts ON llm_call(ts);

CREATE TABLE IF NOT EXISTS view_cache (
    addr         INTEGER NOT NULL,
    kind         TEXT NOT NULL,        -- ghidra_c|ghidra_norm|lifted|lifted_collapsed|packet
    version_hash TEXT,
    path         TEXT,
    tokens       INTEGER,
    lines        INTEGER,
    PRIMARY KEY (addr, kind)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS lesson (
    id         INTEGER PRIMARY KEY,
    key        TEXT UNIQUE,
    title      TEXT,
    body       TEXT,
    trigger    TEXT,                   -- stage name this applies to
    check_kind TEXT,                   -- shell | python | none
    check_ref  TEXT,
    severity   TEXT DEFAULT 'warn',    -- warn | error
    hits       INTEGER DEFAULT 0,
    source     TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS run (
    id          INTEGER PRIMARY KEY,
    stage       TEXT,
    args_json   TEXT,
    inputs_hash TEXT,
    outputs_json TEXT,
    started     TEXT,
    ended       TEXT,
    ok          INTEGER
);
CREATE INDEX IF NOT EXISTS ix_run_stage ON run(stage, inputs_hash);

CREATE TABLE IF NOT EXISTS job (
    id         TEXT PRIMARY KEY,
    cmd        TEXT,
    host       TEXT,
    pid        INTEGER,
    state      TEXT,
    log_path   TEXT,
    started    TEXT,
    ended      TEXT
);
