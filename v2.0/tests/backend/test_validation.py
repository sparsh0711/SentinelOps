import unittest

from backend.errors import ApiError
from backend.validation import bounded_int, validate_analysis, validate_evtx_filename


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


if __name__ == "__main__":
    unittest.main()
