import unittest

from backend.errors import ApiError
from backend.validation import (
    bounded_int,
    validate_analysis,
    validate_detection_settings,
    validate_evtx_filename,
    validate_rule,
)


class ValidationTests(unittest.TestCase):
    def test_valid_analysis_is_normalized(self):
        result = validate_analysis(
            {
                "sourceName": " test.evtx ",
                "events": [],
                "alerts": [],
                "riskScore": "65",
                "riskLevel": "high",
            }
        )
        self.assertEqual(result["riskScore"], 65)
        self.assertEqual(result["riskLevel"], "High")

    def test_missing_analysis_fields_include_details(self):
        with self.assertRaises(ApiError) as context:
            validate_analysis({"sourceName": "test"})
        self.assertIn("events", context.exception.details["missing"])

    def test_bounded_integer_rejects_out_of_range_value(self):
        with self.assertRaises(ApiError):
            bounded_int(101, "riskScore", 0, minimum=0, maximum=100)

    def test_evtx_filename_is_reduced_to_basename(self):
        self.assertEqual(validate_evtx_filename("../../Security.evtx"), "Security.evtx")
        with self.assertRaises(ApiError):
            validate_evtx_filename("payload.exe")

    def test_sigma_inspired_rule_validation(self):
        rule = validate_rule(
            {
                "id": "custom-test-rule",
                "title": "Custom Test Rule",
                "description": "Detects a test command.",
                "level": "medium",
                "confidence": 75,
                "match": {
                    "all": [
                        {"field": "command", "operator": "contains", "value": "test"}
                    ]
                },
                "mitre": {"id": "T1059", "name": "Command Interpreter"},
            }
        )
        self.assertEqual(rule["level"], "Medium")
        self.assertEqual(rule["confidence"], 75)

    def test_detection_settings_normalize_allowlists(self):
        settings = validate_detection_settings(
            {
                "allowlists": {
                    "users": [" svc_backup ", "svc_backup"],
                    "hosts": [],
                    "sourceIps": [],
                    "processes": [],
                },
                "suppressionWindowSeconds": 300,
                "severityOverrides": {"custom": "low"},
                "thresholdOverrides": {
                    "custom": {"count": 3, "windowSeconds": 60}
                },
            }
        )
        self.assertEqual(settings["allowlists"]["users"], ["svc_backup"])
        self.assertEqual(settings["severityOverrides"]["custom"], "Low")


if __name__ == "__main__":
    unittest.main()
