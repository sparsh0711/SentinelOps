CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('Low', 'Medium', 'High')),
    status TEXT NOT NULL CHECK(status IN ('New', 'Investigating', 'Contained', 'Resolved', 'False Positive')),
    owner TEXT NOT NULL DEFAULT '',
    source_name TEXT NOT NULL DEFAULT '',
    alert_id TEXT NOT NULL DEFAULT '',
    rule_id TEXT NOT NULL DEFAULT '',
    mitre_id TEXT NOT NULL DEFAULT '',
    risk_score INTEGER NOT NULL DEFAULT 0,
    payload TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT '[]',
    timeline TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_updated_at ON incidents(updated_at);
