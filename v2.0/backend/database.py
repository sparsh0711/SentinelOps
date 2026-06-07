import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .errors import NotFoundError


MIGRATIONS_DIR = Path(__file__).with_name("migrations")


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
