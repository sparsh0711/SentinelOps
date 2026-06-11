import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .errors import NotFoundError


MIGRATIONS_DIR = Path(__file__).with_name("migrations")
SUMMARY_FIELDS = (
    "id",
    "created_at",
    "updated_at",
    "title",
    "severity",
    "status",
    "owner",
    "source_name",
    "alert_id",
    "rule_id",
    "mitre_id",
    "risk_score",
)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, path):
        self.path = Path(path)

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def migrate(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations "
                "(version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            applied = {
                row["version"]
                for row in connection.execute(
                    "SELECT version FROM schema_migrations"
                ).fetchall()
            }
            for migration in sorted(MIGRATIONS_DIR.glob("*.sql")):
                if migration.stem in applied:
                    continue
                connection.executescript(migration.read_text(encoding="utf-8"))
                connection.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (migration.stem, utc_now()),
                )

    def list_analyses(self, limit=100):
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT id, created_at, source_name, event_count, alert_count,
                       risk_score, risk_level
                FROM analyses ORDER BY id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_analysis(self, analysis_id):
        with self.connect() as connection:
            row = connection.execute(
                "SELECT payload FROM analyses WHERE id = ?", (analysis_id,)
            ).fetchone()
        if not row:
            raise NotFoundError("Analysis not found.")
        return json.loads(row["payload"])

    def save_analysis(self, payload):
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO analyses (
                    created_at, source_name, event_count, alert_count,
                    risk_score, risk_level, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    utc_now(),
                    payload["sourceName"],
                    len(payload["events"]),
                    len(payload["alerts"]),
                    payload["riskScore"],
                    payload["riskLevel"],
                    json.dumps(payload, ensure_ascii=False),
                ),
            )
        return cursor.lastrowid

    def get_checkpoint(self, channel):
        with self.connect() as connection:
            row = connection.execute(
                "SELECT record_id FROM collection_checkpoints WHERE channel = ?",
                (channel,),
            ).fetchone()
        return int(row["record_id"]) if row else 0

    def save_checkpoint(self, channel, record_id):
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO collection_checkpoints(channel, record_id, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(channel) DO UPDATE SET
                    record_id = excluded.record_id,
                    updated_at = excluded.updated_at
                """,
                (channel, int(record_id), utc_now()),
            )

    def reset_checkpoint(self, channel):
        with self.connect() as connection:
            connection.execute(
                "DELETE FROM collection_checkpoints WHERE channel = ?", (channel,)
            )

    def _incident_from_row(self, row, include_payload=False):
        incident = {field: row[field] for field in SUMMARY_FIELDS}
        notes = json.loads(row["notes"] or "[]")
        timeline = json.loads(row["timeline"] or "[]")
        incident["notes_count"] = len(notes)
        incident["timeline_count"] = len(timeline)
        if include_payload:
            incident["payload"] = json.loads(row["payload"] or "{}")
            incident["notes"] = notes
            incident["timeline"] = timeline
        return incident

    def list_incidents(self, limit=100, status=None):
        query = """
            SELECT *
            FROM incidents
        """
        parameters = []
        if status:
            query += " WHERE status = ?"
            parameters.append(status)
        query += " ORDER BY updated_at DESC, id DESC LIMIT ?"
        parameters.append(limit)
        with self.connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [self._incident_from_row(row) for row in rows]

    def get_incident(self, incident_id):
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
        if not row:
            raise NotFoundError("Incident not found.")
        incident = self._incident_from_row(row, include_payload=True)
        incident["summaries"] = self.list_incident_summaries(incident_id)
        return incident

    def create_incident(self, payload):
        now = utc_now()
        timeline = [
            {
                "time": now,
                "actor": payload.get("owner") or "system",
                "action": "Incident created",
                "details": "Created from a detection alert.",
            }
        ]
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO incidents (
                    created_at, updated_at, title, severity, status, owner,
                    source_name, alert_id, rule_id, mitre_id, risk_score,
                    payload, notes, timeline
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    now,
                    payload["title"],
                    payload["severity"],
                    payload["status"],
                    payload["owner"],
                    payload["sourceName"],
                    payload["alertId"],
                    payload["ruleId"],
                    payload["mitreId"],
                    payload["riskScore"],
                    json.dumps(payload, ensure_ascii=False),
                    json.dumps([], ensure_ascii=False),
                    json.dumps(timeline, ensure_ascii=False),
                ),
            )
        return self.get_incident(cursor.lastrowid)

    def update_incident(self, incident_id, patch):
        incident = self.get_incident(incident_id)
        updates = {}
        for key, column in (
            ("title", "title"),
            ("severity", "severity"),
            ("status", "status"),
            ("owner", "owner"),
        ):
            if key in patch and patch[key] != incident[column]:
                updates[column] = patch[key]
        if not updates:
            return incident
        now = utc_now()
        timeline = incident["timeline"]
        changed = ", ".join(f"{key}: {value}" for key, value in updates.items())
        timeline.append(
            {
                "time": now,
                "actor": patch.get("actor") or "analyst",
                "action": "Incident updated",
                "details": changed,
            }
        )
        assignments = ", ".join(f"{column} = ?" for column in updates)
        values = list(updates.values()) + [
            now,
            json.dumps(timeline, ensure_ascii=False),
            incident_id,
        ]
        with self.connect() as connection:
            connection.execute(
                f"""
                UPDATE incidents
                SET {assignments}, updated_at = ?, timeline = ?
                WHERE id = ?
                """,
                values,
            )
        return self.get_incident(incident_id)

    def add_incident_note(self, incident_id, note):
        incident = self.get_incident(incident_id)
        now = utc_now()
        notes = incident["notes"]
        notes.append(
            {
                "time": now,
                "author": note["author"],
                "text": note["text"],
            }
        )
        timeline = incident["timeline"]
        timeline.append(
            {
                "time": now,
                "actor": note["author"],
                "action": "Note added",
                "details": note["text"][:180],
            }
        )
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE incidents
                SET updated_at = ?, notes = ?, timeline = ?
                WHERE id = ?
                """,
                (
                    now,
                    json.dumps(notes, ensure_ascii=False),
                    json.dumps(timeline, ensure_ascii=False),
                    incident_id,
                ),
            )
        return self.get_incident(incident_id)

    def list_incident_summaries(self, incident_id, limit=20):
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT id, incident_id, created_at, provider, model,
                       evidence_hash, payload
                FROM incident_summaries
                WHERE incident_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (incident_id, limit),
            ).fetchall()
        summaries = []
        for row in rows:
            summary = json.loads(row["payload"])
            summary.update(
                {
                    "id": row["id"],
                    "incidentId": row["incident_id"],
                    "createdAt": row["created_at"],
                    "provider": row["provider"],
                    "model": row["model"],
                    "evidenceHash": row["evidence_hash"],
                }
            )
            summaries.append(summary)
        return summaries

    def save_incident_summary(self, incident_id, generated):
        created_at = utc_now()
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO incident_summaries (
                    incident_id, created_at, provider, model,
                    evidence_hash, payload
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    created_at,
                    generated["provider"],
                    generated["model"],
                    generated["evidenceHash"],
                    json.dumps(generated["summary"], ensure_ascii=False),
                ),
            )
        summaries = self.list_incident_summaries(incident_id)
        return next(item for item in summaries if item["id"] == cursor.lastrowid)
