CREATE TABLE detection_rules (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    level TEXT NOT NULL CHECK(level IN ('Low', 'Medium', 'High')),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    source TEXT NOT NULL DEFAULT 'custom',
    rule_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE detection_settings (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
