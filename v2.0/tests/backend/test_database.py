import tempfile
import unittest
from pathlib import Path

from backend.database import Database


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Database(Path(self.temporary.name) / "test.db")
        self.database.migrate()

    def tearDown(self):
        self.temporary.cleanup()

    def test_migrations_are_idempotent(self):
        self.database.migrate()
        with self.database.connect() as connection:
            versions = connection.execute(
                "SELECT version FROM schema_migrations"
            ).fetchall()
        self.assertEqual(
            [row["version"] for row in versions],
            ["001_initial", "002_detection_rules", "003_incidents"],
        )

    def test_analysis_round_trip(self):
        payload = {
            "sourceName": "security.evtx",
            "events": [{"event_id": 4625}],
            "alerts": [{"severity": "Low"}],
            "riskScore": 3,
            "riskLevel": "Low",
        }
        analysis_id = self.database.save_analysis(payload)
        self.assertEqual(self.database.get_analysis(analysis_id), payload)
        self.assertEqual(self.database.list_analyses()[0]["source_name"], "security.evtx")

    def test_checkpoint_round_trip(self):
        self.assertEqual(self.database.get_checkpoint("Security"), 0)
        self.database.save_checkpoint("Security", 42)
        self.assertEqual(self.database.get_checkpoint("Security"), 42)
        self.database.reset_checkpoint("Security")
        self.assertEqual(self.database.get_checkpoint("Security"), 0)

    def test_incident_round_trip(self):
        incident = self.database.create_incident(
            {
                "title": "Suspicious PowerShell",
                "severity": "High",
                "status": "New",
                "owner": "",
                "sourceName": "Security.evtx",
                "alertId": "alert-1",
                "ruleId": "suspicious-powershell",
                "mitreId": "T1059.001",
                "riskScore": 90,
                "description": "Encoded command detected.",
                "evidence": [],
                "alert": {},
            }
        )
        self.assertEqual(incident["title"], "Suspicious PowerShell")
        self.assertEqual(self.database.list_incidents()[0]["id"], incident["id"])

        updated = self.database.update_incident(
            incident["id"],
            {"status": "Investigating", "owner": "Sparsh", "actor": "Sparsh"},
        )
        self.assertEqual(updated["status"], "Investigating")
        self.assertEqual(updated["owner"], "Sparsh")

        noted = self.database.add_incident_note(
            incident["id"], {"author": "Sparsh", "text": "Checked source host."}
        )
        self.assertEqual(noted["notes"][0]["text"], "Checked source host.")
        self.assertGreaterEqual(len(noted["timeline"]), 3)


if __name__ == "__main__":
    unittest.main()
