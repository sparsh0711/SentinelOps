import unittest
from types import SimpleNamespace

from backend.ai_summary import SummaryEngine, build_evidence_packet


class AiSummaryTests(unittest.TestCase):
    def setUp(self):
        self.settings = SimpleNamespace(
            openai_api_key="",
            openai_model="gpt-5.5",
            ai_timeout_seconds=10,
        )
        self.incident = {
            "id": 7,
            "title": "Correlated authentication and PowerShell activity",
            "severity": "High",
            "status": "New",
            "source_name": "Security.evtx",
            "risk_score": 88,
            "rule_id": "correlated",
            "mitre_id": "T1110",
            "payload": {
                "alerts": [
                    {
                        "id": "failed-login",
                        "title": "Repeated failed logins",
                        "description": "Five failed logins from 203.0.113.10.",
                        "severity": "High",
                        "sourceIp": "203.0.113.10",
                        "mitre": {"id": "T1110.001", "name": "Password Guessing"},
                    },
                    {
                        "id": "powershell",
                        "title": "Suspicious PowerShell",
                        "description": "Encoded PowerShell command observed.",
                        "severity": "High",
                        "mitre": {"id": "T1059.001", "name": "PowerShell"},
                    },
                ],
                "evidence": [
                    {
                        "eventId": "4625",
                        "sourceIp": "203.0.113.10",
                        "user": "analyst",
                        "secretField": "must-not-leave",
                    }
                ],
            },
        }

    def test_evidence_packet_only_contains_allowlisted_event_fields(self):
        packet, evidence_hash = build_evidence_packet(self.incident)
        self.assertEqual(len(evidence_hash), 64)
        self.assertNotIn("secretField", packet["events"][0])
        self.assertEqual(packet["events"][0]["sourceIp"], "203.0.113.10")

    def test_local_summary_is_grounded_and_structured(self):
        generated = SummaryEngine(self.settings).generate(self.incident)
        self.assertEqual(generated["provider"], "local-evidence")
        summary = generated["summary"]
        self.assertIn("2 alerts", summary["executiveSummary"])
        self.assertEqual(
            [item["id"] for item in summary["mitreTechniques"]],
            ["T1110.001", "T1059.001"],
        )
        self.assertIn("No additional risk was inferred", summary["riskExplanation"])


if __name__ == "__main__":
    unittest.main()
