import tempfile
import unittest
from pathlib import Path

from backend.ai_summary import SummaryEngine
from backend.api import Api
from backend.config import Settings
from backend.database import Database
from backend.errors import ApiError
from backend.rules import RuleRepository


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
        self.rules = RuleRepository(self.database)
        self.rules.seed_builtin_rules()
        self.api = Api(
            self.settings,
            self.database,
            self.rules,
            SummaryEngine(self.settings),
        )

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

    def test_rules_and_detection_settings_round_trip(self):
        listing, status = self.api.get("/api/v2/rules", "")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(len(listing["rules"]), 4)
        settings, _ = self.api.post_json(
            "/api/v2/detection-settings",
            {
                "allowlists": {
                    "users": ["svc_backup"],
                    "hosts": [],
                    "sourceIps": [],
                    "processes": [],
                },
                "suppressionWindowSeconds": 600,
                "severityOverrides": {},
                "thresholdOverrides": {},
            },
        )
        self.assertEqual(settings["allowlists"]["users"], ["svc_backup"])
        self.assertEqual(settings["suppressionWindowSeconds"], 600)

    def test_incident_api_round_trip(self):
        created, status = self.api.post_json(
            "/api/v2/incidents",
            {
                "sourceName": "Security.evtx",
                "alert": {
                    "id": "alert-1",
                    "ruleId": "suspicious-powershell",
                    "title": "Suspicious PowerShell",
                    "description": "Encoded command detected.",
                    "severity": "High",
                    "riskScore": 92,
                    "mitre": {"id": "T1059.001", "name": "PowerShell"},
                },
            },
        )
        self.assertEqual(status, 201)
        self.assertEqual(created["status"], "New")

        listing, status = self.api.get("/api/v2/incidents", "")
        self.assertEqual(status, 200)
        self.assertEqual(listing["incidents"][0]["id"], created["id"])

        updated, status = self.api.post_json(
            f"/api/v2/incidents/{created['id']}/update",
            {"status": "Contained", "owner": "Sparsh"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(updated["status"], "Contained")

        noted, status = self.api.post_json(
            f"/api/v2/incidents/{created['id']}/notes",
            {"author": "Sparsh", "text": "Isolated the affected host."},
        )
        self.assertEqual(status, 200)
        self.assertEqual(noted["notes"][0]["author"], "Sparsh")

        summary, status = self.api.post_json(
            f"/api/v2/incidents/{created['id']}/summaries", {}
        )
        self.assertEqual(status, 201)
        self.assertEqual(summary["provider"], "local-evidence")
        opened, _ = self.api.get(f"/api/v2/incidents/{created['id']}", "")
        self.assertEqual(opened["summaries"][0]["id"], summary["id"])


if __name__ == "__main__":
    unittest.main()
