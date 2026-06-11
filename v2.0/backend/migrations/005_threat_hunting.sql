CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    UNIQUE(type, value)
);

CREATE INDEX IF NOT EXISTS idx_iocs_type_enabled
ON iocs(type, enabled);

CREATE TABLE IF NOT EXISTS hunt_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    hunt_id TEXT NOT NULL,
    source_name TEXT NOT NULL,
    match_count INTEGER NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hunt_runs_created_at
ON hunt_runs(created_at DESC);
