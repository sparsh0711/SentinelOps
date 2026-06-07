import tempfile
import unittest
from pathlib import Path

from backend.api import Api
from backend.config import Settings
from backend.database import Database
from backend.errors import ApiError


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.settings = Settings(
            host="127.0.0.1",
            port=0,
            database=root / "test.db",
            static_dir=root,
            log_level="CRITICAL",
            max_upload_bytes=1024,
            max_events=5000,
        )
        self.database = Database(self.settings.database)
        self.database.migrate()
        self.api = Api(self.settings, self.database)

    def tearDown(self):
        self.temporary.cleanup()

    def test_status_is_versioned(self):
        payload, status = self.api.get("/api/v2/status", "")
        self.assertEqual(status, 200)
        self.assertEqual(payload["api"], "/api/v2")
        self.assertTrue(payload["version"].startswith("2.0.0"))

    def test_analysis_create_and_list(self):
        payload = {
            "sourceName": "events.json",
            "events": [],
            "alerts": [],
            "riskScore": 0,
            "riskLevel": "Low",
        }
        created, status = self.api.post_json("/api/v2/analyses", payload)
        self.assertEqual(status, 201)
        listing, _ = self.api.get("/api/v2/analyses", "")
        self.assertEqual(listing["analyses"][0]["id"], created["id"])

    def test_unknown_endpoint_uses_structured_error(self):
        with self.assertRaises(ApiError) as context:
            self.api.get("/api/v2/missing", "")
        self.assertEqual(context.exception.code, "not_found")
        self.assertEqual(context.exception.status, 404)


if __name__ == "__main__":
    unittest.main()
