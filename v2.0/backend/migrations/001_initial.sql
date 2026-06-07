CREATE TABLE analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    source_name TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    alert_count INTEGER NOT NULL,
    risk_score INTEGER NOT NULL CHECK(risk_score BETWEEN 0 AND 100),
    risk_level TEXT NOT NULL CHECK(risk_level IN ('Low', 'Medium', 'High')),
    payload TEXT NOT NULL
);

CREATE TABLE collection_checkpoints (
    channel TEXT PRIMARY KEY,
    record_id INTEGER NOT NULL CHECK(record_id >= 0),
    updated_at TEXT NOT NULL
);
