import json
import unittest
from unittest.mock import Mock

from scripts.run_eval import evaluate_response, read_internal_token


class TestEvaluationChecks(unittest.TestCase):
    def setUp(self):
        self.scenario = {
            "expected_mitre": "T1110",
            "must_mention": ["SSH", "failed login"],
            "must_not_claim": ["confirmed attack", "successful breach"],
        }

    def response(self, payload, status=200):
        response = Mock()
        response.status = status
        response.read.return_value = json.dumps(payload).encode("utf-8")
        return response

    def test_mock_success_response_passes_all_checks(self):
        response = self.response(
            {
                "ok": True,
                "analysis": "T1110: SSH event with a failed login. Verify evidence.",
            }
        )

        checks = evaluate_response(response, self.scenario)

        self.assertEqual(
            checks,
            {
                "api": True,
                "mitre": True,
                "keywords": True,
                "claims": True,
                "overall": True,
            },
        )

    def test_mock_response_fails_missing_keywords_and_disallowed_claim(self):
        response = self.response(
            {
                "ok": True,
                "analysis": "T1110. Confirmed attack and successful breach.",
            }
        )

        checks = evaluate_response(response, self.scenario)

        self.assertTrue(checks["api"])
        self.assertTrue(checks["mitre"])
        self.assertFalse(checks["keywords"])
        self.assertFalse(checks["claims"])
        self.assertFalse(checks["overall"])

    def test_mock_error_response_fails_all_checks(self):
        checks = evaluate_response(
            self.response({"ok": False, "error": "unavailable"}, status=503),
            self.scenario,
        )

        self.assertEqual(
            checks,
            {
                "api": False,
                "mitre": False,
                "keywords": False,
                "claims": False,
                "overall": False,
            },
        )

    def test_synonym_group_accepts_one_equivalent_phrase(self):
        scenario = {
            "expected_mitre": "T1571",
            "must_mention": [
                "T1571",
                "connection",
                ["non-standard port", "unusual port", "uncommon port"],
            ],
            "must_not_claim": ["confirmed attack"],
        }
        response = self.response(
            {
                "ok": True,
                "analysis": "T1571: Review this suspicious connection on an unusual port.",
            }
        )

        checks = evaluate_response(response, scenario)

        self.assertTrue(checks["keywords"])
        self.assertTrue(checks["overall"])

    def test_synonym_group_still_fails_if_no_option_appears(self):
        scenario = {
            "expected_mitre": "T1571",
            "must_mention": [
                "T1571",
                "connection",
                ["non-standard port", "unusual port", "uncommon port"],
            ],
            "must_not_claim": ["confirmed attack"],
        }
        response = self.response(
            {"ok": True, "analysis": "T1571: Review this suspicious connection."}
        )

        checks = evaluate_response(response, scenario)

        self.assertFalse(checks["keywords"])
        self.assertFalse(checks["overall"])

    def test_token_reader_returns_value_without_printing_it(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from contextlib import redirect_stdout
        from io import StringIO

        with TemporaryDirectory() as temp_dir:
            env_file = Path(temp_dir) / ".env"
            env_file.write_text(
                "GROQ_API_KEY=synthetic-key-placeholder\n"
                "SOC_AI_INTERNAL_TOKEN=synthetic-token-value\n",
                encoding="utf-8",
            )
            output = StringIO()
            with redirect_stdout(output):
                token = read_internal_token(env_file)

        self.assertEqual(token, "synthetic-token-value")
        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
