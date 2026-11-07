import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from unittest.mock import Mock

from scripts.run_eval import (
    evaluate_response,
    markdown_report,
    read_internal_token,
    run_scenario,
    run_scenarios,
)


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

    def test_mitre_from_input_is_reported_but_not_counted_in_overall(self):
        scenario = {
            "expected_mitre": "T1110",
            "mitre_in_input": True,
            "must_mention": ["SSH"],
            "must_not_claim": ["confirmed attack"],
        }
        checks = evaluate_response(
            self.response({"ok": True, "analysis": "SSH logins require review."}),
            scenario,
        )

        self.assertFalse(checks["mitre"])
        self.assertTrue(checks["overall"])
        report = markdown_report(
            [{"scenario": "SYNTHETIC: Existing mapping", "checks": checks,
              "mitre_in_input": True, "duration_ms": 1}]
        )
        self.assertIn("yes (not independent)", report)
        self.assertIn("excluded from the overall result", report)

    def test_scenario_without_expected_mitre_has_no_mitre_check(self):
        scenario = {
            "expected_mitre": None,
            "mitre_in_input": False,
            "must_mention": ["routine"],
            "must_not_claim": ["confirmed breach"],
        }
        checks = evaluate_response(
            self.response({"ok": True, "analysis": "Routine event."}), scenario
        )
        self.assertIsNone(checks["mitre"])
        self.assertTrue(checks["overall"])

    def test_run_scenario_saves_response_body_without_request_credentials(self):
        from scripts import run_eval

        payload = json.dumps({"ok": True, "analysis": "T1110 SSH failed login."}).encode()
        mocked_response = Mock()
        mocked_response.status = 200
        mocked_response.read.return_value = payload
        mocked_response.__enter__ = Mock(return_value=mocked_response)
        mocked_response.__exit__ = Mock(return_value=False)
        scenario = {
            "name": "SYNTHETIC: SSH check",
            "alert": {"rule": {"mitre": {"id": ["T1110"]}}},
            "expected_mitre": "T1110",
            "mitre_in_input": True,
            "must_mention": ["SSH"],
            "must_not_claim": ["confirmed attack"],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "eval-responses"
            with patch.object(run_eval.urllib.request, "urlopen", return_value=mocked_response) as urlopen:
                result = run_scenario(scenario, "synthetic-token", 5000, output_dir)

            saved = (output_dir / "synthetic-ssh-check.json").read_bytes()
            request = urlopen.call_args.args[0]

        self.assertTrue(result["checks"]["overall"])
        self.assertEqual(saved, payload)
        self.assertNotIn(b"synthetic-token", saved)
        self.assertNotIn(b"synthetic-token", request.data)
        self.assertEqual(request.get_header("Authorization"), "Bearer synthetic-token")

    def test_delay_is_applied_only_between_scenarios(self):
        from scripts import run_eval

        scenarios = [{"name": "one"}, {"name": "two"}, {"name": "three"}]
        expected = [{"scenario": item["name"]} for item in scenarios]
        with patch.object(run_eval, "run_scenario", side_effect=expected) as run, patch.object(
            run_eval.time, "sleep"
        ) as sleep:
            results = run_scenarios(scenarios, "token", 5000, delay=0.25)

        self.assertEqual(results, expected)
        self.assertEqual(run.call_count, 3)
        self.assertEqual(sleep.call_count, 2)
        sleep.assert_called_with(0.25)


if __name__ == "__main__":
    unittest.main()
