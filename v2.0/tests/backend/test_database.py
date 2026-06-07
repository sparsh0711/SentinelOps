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
            ["001_initial", "002_detection_rules"],
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


if __name__ == "__main__":
    unittest.main()
