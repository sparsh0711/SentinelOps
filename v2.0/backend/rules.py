import json
from pathlib import Path

from .database import utc_now
from .errors import NotFoundError


BUILTIN_RULES_PATH = Path(__file__).resolve().parents[1] / "rules" / "default_rules.json"
DEFAULT_SETTINGS = {
    "allowlists": {"users": [], "hosts": [], "sourceIps": [], "processes": []},
    "suppressionWindowSeconds": 300,
    "severityOverrides": {},
    "thresholdOverrides": {},
}


class RuleRepository:
    def __init__(self, database):
        self.database = database

    def seed_builtin_rules(self):
        rules = json.loads(BUILTIN_RULES_PATH.read_text(encoding="utf-8"))
        existing = {rule["id"] for rule in self.list_rules()}
        for rule in rules:
            if rule["id"] not in existing:
                self.save_rule(rule, source="builtin")
        if self.get_settings() == DEFAULT_SETTINGS:
            self.save_settings(DEFAULT_SETTINGS)

    def list_rules(self):
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT rule_json, enabled, source FROM detection_rules ORDER BY title"
            ).fetchall()
        rules = []
        for row in rows:
            rule = json.loads(row["rule_json"])
            rule["enabled"] = bool(row["enabled"])
            rule["source"] = row["source"]
            rules.append(rule)
        return rules

    def get_rule(self, rule_id):
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT rule_json, enabled, source FROM detection_rules WHERE id = ?",
                (rule_id,),
            ).fetchone()
        if not row:
            raise NotFoundError("Detection rule not found.")
        rule = json.loads(row["rule_json"])
        rule["enabled"] = bool(row["enabled"])
        rule["source"] = row["source"]
        return rule

    def save_rule(self, rule, source="custom"):
        now = utc_now()
        serialized = json.dumps(rule, ensure_ascii=False)
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO detection_rules(
                    id, title, level, enabled, source, rule_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    title = excluded.title,
                    level = excluded.level,
                    enabled = excluded.enabled,
                    source = excluded.source,
                    rule_json = excluded.rule_json,
                    updated_at = excluded.updated_at
                """,
                (rule["id"], rule["title"], rule["level"], int(rule.get("enabled", True)), source, serialized, now, now),
            )
        return self.get_rule(rule["id"])

    def set_enabled(self, rule_id, enabled):
        self.get_rule(rule_id)
        with self.database.connect() as connection:
            connection.execute(
                "UPDATE detection_rules SET enabled = ?, updated_at = ? WHERE id = ?",
                (int(enabled), utc_now(), rule_id),
            )
        return self.get_rule(rule_id)

    def delete_rule(self, rule_id):
        rule = self.get_rule(rule_id)
        if rule["source"] == "builtin":
            raise ValueError("Built-in rules cannot be deleted; disable them instead.")
        with self.database.connect() as connection:
            connection.execute("DELETE FROM detection_rules WHERE id = ?", (rule_id,))

    def get_settings(self):
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT value_json FROM detection_settings WHERE key = 'engine'"
            ).fetchone()
        return json.loads(row["value_json"]) if row else {
            "allowlists": {key: list(value) for key, value in DEFAULT_SETTINGS["allowlists"].items()},
            "suppressionWindowSeconds": DEFAULT_SETTINGS["suppressionWindowSeconds"],
            "severityOverrides": {},
            "thresholdOverrides": {},
        }

    def save_settings(self, settings):
        with self.database.connect() as connection:
            connection.execute(
                """
                INSERT INTO detection_settings(key, value_json, updated_at)
                VALUES ('engine', ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value_json = excluded.value_json,
                    updated_at = excluded.updated_at
                """,
                (json.dumps(settings, ensure_ascii=False), utc_now()),
            )
        return self.get_settings()
