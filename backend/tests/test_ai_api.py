import os
import unittest
from unittest.mock import Mock, patch

from app import app
from groq_service import GroqUnavailable, generate_investigation_report


INTERNAL_TOKEN = "unit-test-internal-token"
ENDPOINT = "/api/ai/analyze-alert"


class TestAnalyzeAlertAPI(unittest.TestCase):
    def setUp(self):
        self.env_patch = patch.dict(
            os.environ,
            {"SOC_AI_INTERNAL_TOKEN": INTERNAL_TOKEN},
        )
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        self.client = app.test_client()
        self.headers = {"Authorization": f"Bearer {INTERNAL_TOKEN}"}

    def post_alert(self, alert, headers=None):
        return self.client.post(
            ENDPOINT,
            json={"alert": alert},
            headers=self.headers if headers is None else headers,
        )

    def test_missing_token_is_rejected(self):
        response = self.client.post(ENDPOINT, json={"alert": {"rule": {}}})
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.get_json()["ok"])

    def test_missing_server_token_configuration_is_rejected(self):
        with patch.dict(os.environ, {"SOC_AI_INTERNAL_TOKEN": ""}):
            response = self.post_alert({"rule": {"id": "1001"}})
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.get_json()["ok"])

    def test_incorrect_token_is_rejected(self):
        response = self.post_alert(
            {"rule": {"id": "1001"}},
            headers={"Authorization": "Bearer incorrect-token"},
        )
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.get_json()["ok"])

    def test_valid_token_analyzes_only_sanitized_alert(self):
        original = {
            "rule": {"id": "1001", "description": "Synthetic test"},
            "password": "private",
            "full_log": "raw secret log",
        }

        with patch("app.explain_alert", return_value="Analysis text") as explain:
            response = self.post_alert(original)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {"ok": True, "analysis": "Analysis text"},
        )
        self.assertEqual(
            explain.call_args.args[0],
            {"rule": {"id": "1001", "description": "Synthetic test"}},
        )

    def test_non_allowlisted_alert_fields_never_reach_groq(self):
        from types import SimpleNamespace

        completion = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))]
        )
        create = Mock(return_value=completion)
        client = SimpleNamespace(
            chat=SimpleNamespace(completions=SimpleNamespace(create=create))
        )
        alert = {
            "rule": {"id": "1001"},
            "data": {
                "dstip": "192.168.1.7",
                "dstuser": "synthetic-user-value",
            },
            "full_log": "synthetic-full-log-value",
        }

        with patch.dict(os.environ, {"GROQ_API_KEY": "synthetic-test-key"}), patch(
            "groq_service.Groq", return_value=client
        ):
            response = self.post_alert(alert)

        self.assertEqual(response.status_code, 200)
        messages = create.call_args.kwargs["messages"]
        serialized_messages = str(messages)
        for excluded in (
            "full_log",
            "synthetic-full-log-value",
            "dstuser",
            "synthetic-user-value",
        ):
            self.assertNotIn(excluded, serialized_messages)

    def test_alert_with_no_allowlisted_fields_returns_422(self):
        with patch("app.explain_alert") as explain:
            response = self.post_alert(
                {
                    "full_log": "synthetic raw log",
                    "data": {"dstuser": "synthetic-user"},
                }
            )

        self.assertEqual(response.status_code, 422)
        self.assertEqual(
            response.get_json(),
            {"ok": False, "error": "Alert has no analyzable fields"},
        )
        explain.assert_not_called()

    def test_private_addresses_are_pseudonymized_before_alert_analysis(self):
        alert = {
            "data": {"srcip": "192.168.5.10", "dstip": "192.168.5.10"},
            "rule": {"description": "Connection from 192.168.5.10"},
        }
        with patch("app.explain_alert", return_value="Synthetic analysis") as explain:
            response = self.post_alert(alert)

        self.assertEqual(response.status_code, 200)
        supplied_alert = explain.call_args.args[0]
        pseudonyms = (
            supplied_alert["data"]["srcip"],
            supplied_alert["data"]["dstip"],
            supplied_alert["rule"]["description"].split()[-1],
        )
        self.assertEqual(len(set(pseudonyms)), 1)
        self.assertNotIn("192.168.5.10", str(supplied_alert))
        self.assertEqual(alert["data"]["srcip"], "192.168.5.10")

    def test_missing_or_invalid_alert_is_rejected(self):
        invalid_payloads = (
            {},
            {"alert": None},
            {"alert": []},
            {"alert": "text"},
            {"alert": {}},
        )
        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                response = self.client.post(
                    ENDPOINT,
                    json=payload,
                    headers=self.headers,
                )
                self.assertEqual(response.status_code, 400)
                self.assertFalse(response.get_json()["ok"])

    def test_malformed_json_is_rejected(self):
        response = self.client.post(
            ENDPOINT,
            data="{malformed",
            content_type="application/json",
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.get_json()["ok"])

    def test_unsupported_content_type_is_rejected(self):
        response = self.client.post(
            ENDPOINT,
            data='{"alert": {"rule": {}}}',
            content_type="text/plain",
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 400)

    def test_provider_failure_returns_safe_json_error(self):
        with patch(
            "app.sanitize_alert", side_effect=lambda alert, **kwargs: alert
        ), patch(
            "app.explain_alert",
            side_effect=GroqUnavailable("private provider detail"),
        ):
            response = self.post_alert({"rule": {"id": "1001"}})

        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.get_json(),
            {
                "ok": False,
                "error": "AI analysis is temporarily unavailable",
            },
        )
        self.assertNotIn(b"private provider detail", response.data)

    def test_unexpected_error_returns_safe_json(self):
        with patch(
            "app.sanitize_alert", side_effect=lambda alert, **kwargs: alert
        ), patch(
            "app.explain_alert", side_effect=RuntimeError("private detail")
        ):
            response = self.post_alert({"rule": {"id": "1001"}})

        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.get_json(),
            {"ok": False, "error": "AI analysis could not be completed"},
        )
        self.assertNotIn(b"private detail", response.data)

    def test_oversized_request_returns_json_error(self):
        oversized_body = b'{"alert":{"value":"' + b"x" * (1024 * 1024) + b'"}}'
        response = self.client.post(
            ENDPOINT,
            data=oversized_body,
            content_type="application/json",
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(
            response.get_json(),
            {"ok": False, "error": "Request body is too large"},
        )


class TestGenerateReportAPI(unittest.TestCase):
    def setUp(self):
        self.env_patch = patch.dict(
            os.environ,
            {"SOC_AI_INTERNAL_TOKEN": INTERNAL_TOKEN},
        )
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        self.client = app.test_client()
        self.headers = {"Authorization": f"Bearer {INTERNAL_TOKEN}"}
        self.payload = {
            "evidence": {
                "index": "wazuh-alerts-4.x-2026.10.25",
                "id": "synthetic-alert-id",
                "alert": {
                    "@timestamp": "2026-10-25T10:00:00Z",
                    "rule": {
                        "id": "1001",
                        "mitre": {"technique": ["T1110"]},
                        "description": "Synthetic login failure from 8.8.8.8",
                        "unsupported_field": "must not leave this process",
                    },
                    "data": {
                        "srcip": "8.8.8.8",
                        "authentication_result": "failed",
                        "password": "synthetic-secret",
                    },
                    "full_log": "unfiltered synthetic raw log",
                    "email": "analyst@example.invalid",
                },
            },
            "analyst_notes": "Synthetic context analyst@example.invalid",
        }

    def post_report(self, payload=None, headers=None):
        return self.client.post(
            "/api/ai/generate-report",
            json=self.payload if payload is None else payload,
            headers=self.headers if headers is None else headers,
        )

    def post_alert(self, alert, headers=None):
        return self.client.post(
            ENDPOINT,
            json={"alert": alert},
            headers=self.headers if headers is None else headers,
        )

    def test_missing_or_incorrect_token_is_rejected(self):
        with patch("app.generate_investigation_report") as generate:
            response = self.post_report(headers={"Authorization": "Bearer wrong"})

        self.assertEqual(response.status_code, 401)
        generate.assert_not_called()

    def test_missing_server_token_is_rejected(self):
        with patch.dict(os.environ, {"SOC_AI_INTERNAL_TOKEN": ""}):
            response = self.post_report()
        self.assertEqual(response.status_code, 401)

    def test_invalid_payloads_are_rejected(self):
        invalid = [
            {},
            {"evidence": self.payload["evidence"], "unexpected": "value"},
            {"evidence": {**self.payload["evidence"], "extra": "value"}},
            {"evidence": {**self.payload["evidence"], "index": "other-index"}},
            {"evidence": {**self.payload["evidence"], "index": "wazuh-alerts-5.x-2026.10.25"}},
            {"evidence": {**self.payload["evidence"], "id": ""}},
            {"evidence": {**self.payload["evidence"], "alert": []}},
            {"evidence": self.payload["evidence"], "analyst_notes": []},
            {
                "evidence": self.payload["evidence"],
                "analyst_notes": "x" * 4001,
            },
        ]
        with patch("app.generate_investigation_report") as generate:
            for payload in invalid:
                with self.subTest(payload=payload):
                    response = self.post_report(payload)
                    self.assertEqual(response.status_code, 400)
                    self.assertFalse(response.get_json()["ok"])
        generate.assert_not_called()

    def test_malformed_and_non_json_requests_are_rejected(self):
        malformed = self.client.post(
            "/api/ai/generate-report",
            data="{malformed",
            content_type="application/json",
            headers=self.headers,
        )
        non_json = self.client.post(
            "/api/ai/generate-report",
            data="not-json",
            content_type="text/plain",
            headers=self.headers,
        )
        self.assertEqual(malformed.status_code, 400)
        self.assertEqual(non_json.status_code, 400)

    def test_oversized_request_is_rejected(self):
        oversized = {
            "evidence": self.payload["evidence"],
            "analyst_notes": "x" * (256 * 1024),
        }
        response = self.post_report(oversized)
        self.assertEqual(response.status_code, 413)

    def test_global_oversized_report_request_returns_json_error(self):
        response = self.client.post(
            "/api/ai/generate-report",
            data=b"x" * (1024 * 1024 + 1),
            content_type="application/json",
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(
            response.get_json(),
            {"ok": False, "error": "Report request is too large"},
        )

    def test_evidence_and_notes_are_minimized_and_sanitized(self):
        report = "Synthetic report draft"
        with patch("app.generate_investigation_report", return_value=report) as generate:
            response = self.post_report()

        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertEqual(set(result), {"ok", "status", "evidence", "report"})
        self.assertIs(result["ok"], True)
        self.assertEqual(result["status"], "ai_generated_unverified")
        self.assertEqual(
            result["evidence"],
            {
                "index": "wazuh-alerts-4.x-2026.10.25",
                "id": "synthetic-alert-id",
                "alert": {
                    "@timestamp": "2026-10-25T10:00:00Z",
                    "rule": {
                        "id": "1001",
                        "mitre": {"technique": ["T1110"]},
                        "description": "Synthetic login failure from [REDACTED_PUBLIC_IP]",
                    },
                    "data": {
                        "srcip": "[REDACTED_PUBLIC_IP]",
                        "authentication_result": "failed",
                    },
                },
            },
        )
        self.assertIsInstance(result["report"], str)
        self.assertTrue(result["report"].strip())
        serialized = str(result["evidence"])
        self.assertNotIn("synthetic-secret", serialized)
        self.assertNotIn("unfiltered synthetic raw log", serialized)
        self.assertNotIn("analyst@example.invalid", serialized)
        call_args = generate.call_args.args
        self.assertEqual(call_args[0]["rule"]["id"], "1001")
        self.assertEqual(call_args[0]["rule"]["mitre"]["technique"], ["T1110"])
        self.assertNotIn("unsupported_field", str(call_args[0]))
        self.assertNotIn("full_log", str(call_args[0]))
        self.assertIn("[REDACTED_EMAIL]", call_args[1])

    def test_private_addresses_are_pseudonymized_across_evidence_and_notes(self):
        payload = {
            "evidence": {
                "index": "wazuh-alerts-4.x-2026.10.25",
                "id": "synthetic-alert-id",
                "alert": {
                    "rule": {"description": "Observed 10.12.0.8 and fd12::8"},
                    "data": {"srcip": "10.12.0.8", "dstip": "fd12::8"},
                },
            },
            "analyst_notes": "Repeated 10.12.0.8 and fd12::8",
        }
        original_alert = payload["evidence"]["alert"]
        with patch("app.generate_investigation_report", return_value="draft") as generate:
            response = self.post_report(payload)

        self.assertEqual(response.status_code, 200)
        alert = generate.call_args.args[0]
        notes = generate.call_args.args[1]
        ipv4 = alert["data"]["srcip"]
        ipv6 = alert["data"]["dstip"]
        self.assertEqual(alert["rule"]["description"], f"Observed {ipv4} and {ipv6}")
        self.assertEqual(notes, f"Repeated {ipv4} and {ipv6}")
        self.assertNotIn("10.12.0.8", str((alert, notes)))
        self.assertNotIn("fd12::8", str((alert, notes)))
        self.assertEqual(original_alert["data"]["srcip"], "10.12.0.8")

    def test_numeric_and_encoded_report_evidence_and_notes_are_sanitized(self):
        payload = {
            "evidence": {
                "index": "wazuh-alerts-4.x-2026.10.25",
                "id": "synthetic-alert-id",
                "alert": {
                    "rule": {"description": "Observed IP 0xC0A80107"},
                    "data": {"srcip": 3232235783, "dstip": "0xC0A80107"},
                },
            },
            "analyst_notes": (
                "dstip=3232235783 encoded=%2531%2539%2532%252E%2531%2536%2538"
                "%252E%2531%252E%2537"
            ),
        }
        with patch("app.generate_investigation_report", return_value="draft") as generate:
            response = self.post_report(payload)

        self.assertEqual(response.status_code, 200)
        safe_alert, safe_notes = generate.call_args.args
        address = safe_alert["data"]["srcip"]
        self.assertEqual(safe_alert["data"]["dstip"], address)
        self.assertEqual(safe_alert["rule"]["description"], f"Observed IP {address}")
        self.assertEqual(safe_notes.count(address), 2)
        self.assertNotIn("3232235783", str((safe_alert, safe_notes)))
        self.assertNotIn("0xC0A80107", str((safe_alert, safe_notes)))
        self.assertNotIn("%2531", safe_notes)


    def test_every_provider_prompt_is_sanitized_before_transmission(self):
        from types import SimpleNamespace
        from groq_service import _generate

        completion = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))]
        )
        client = SimpleNamespace(
            chat=SimpleNamespace(
                completions=SimpleNamespace(create=Mock(return_value=completion))
            )
        )
        with patch.dict(os.environ, {"GROQ_API_KEY": "synthetic-test-key"}), patch(
            "groq_service.Groq", return_value=client
        ):
            result = _generate(
                "Private 192.168.3.4 and fd00::4; public 8.8.8.8; context 10.20.0.1",
                system_prompt="System context 10.20.0.1",
            )

        self.assertEqual(result, "ok")
        sent_prompt = client.chat.completions.create.call_args.kwargs["messages"][1]["content"]
        self.assertNotIn("192.168.3.4", sent_prompt)
        self.assertNotIn("fd00::4", sent_prompt)
        self.assertNotIn("8.8.8.8", sent_prompt)
        self.assertIn("[NONPUBLIC_IP_", sent_prompt)
        self.assertIn("[REDACTED_PUBLIC_IP]", sent_prompt)
        sent_system_prompt = client.chat.completions.create.call_args.kwargs[
            "messages"
        ][0]["content"]
        self.assertNotIn("10.20.0.1", sent_system_prompt)
        self.assertIn(
            sent_system_prompt.split("System context ", 1)[1], sent_prompt
        )

    def test_model_is_read_from_environment_at_call_time(self):
        from types import SimpleNamespace
        from groq_service import _generate

        completion = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))]
        )
        create = Mock(return_value=completion)
        client = SimpleNamespace(
            chat=SimpleNamespace(completions=SimpleNamespace(create=create))
        )
        with patch.dict(
            os.environ,
            {"GROQ_API_KEY": "synthetic-test-key", "GROQ_MODEL": "custom/model"},
        ), patch("groq_service.Groq", return_value=client):
            _generate("test prompt")

        self.assertEqual(create.call_args.kwargs["model"], "custom/model")

    def test_reasoning_parameters_are_limited_to_gpt_oss_models(self):
        from types import SimpleNamespace
        from groq_service import _generate

        for model_name, should_include_reasoning in (
            ("openai/gpt-oss-20b", True),
            ("llama-3.3-70b-versatile", False),
        ):
            with self.subTest(model=model_name):
                completion = SimpleNamespace(
                    choices=[
                        SimpleNamespace(message=SimpleNamespace(content="ok"))
                    ]
                )
                create = Mock(return_value=completion)
                client = SimpleNamespace(
                    chat=SimpleNamespace(
                        completions=SimpleNamespace(create=create)
                    )
                )
                with patch.dict(
                    os.environ,
                    {
                        "GROQ_API_KEY": "synthetic-test-key",
                        "GROQ_MODEL": model_name,
                    },
                ), patch("groq_service.Groq", return_value=client):
                    _generate("test prompt")

                call_params = create.call_args.kwargs
                self.assertEqual(call_params["model"], model_name)
                self.assertEqual(
                    "reasoning_effort" in call_params,
                    should_include_reasoning,
                )
                self.assertEqual(
                    "include_reasoning" in call_params,
                    should_include_reasoning,
                )

    def test_legacy_report_improvement_sanitizes_analyst_notes(self):
        from types import SimpleNamespace
        from groq_service import improve_report

        completion = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="improved"))]
        )
        create = Mock(return_value=completion)
        client = SimpleNamespace(
            chat=SimpleNamespace(completions=SimpleNamespace(create=create))
        )
        with patch.dict(os.environ, {"GROQ_API_KEY": "synthetic-test-key"}), patch(
            "groq_service.Groq", return_value=client
        ):
            self.assertEqual(
                improve_report("Investigated 172.16.4.20 and ::1"),
                "improved",
            )

        sent_prompt = create.call_args.kwargs["messages"][1]["content"]
        self.assertNotIn("172.16.4.20", sent_prompt)
        self.assertNotIn("::1", sent_prompt)
        self.assertEqual(sent_prompt.count("[NONPUBLIC_IP_"), 2)

    def test_strict_privacy_configuration_at_provider_boundary(self):
        from types import SimpleNamespace
        from groq_service import _generate

        cases = (
            ("true", True),
            ("1", False),
            ("yes", False),
            ("on", False),
            ("TRUE", False),
            ("True", False),
            ("false", False),
            ("", False),
            (None, False),
        )
        for configured_value, strict_enabled in cases:
            with self.subTest(value=configured_value):
                completion = SimpleNamespace(
                    choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))]
                )
                create = Mock(return_value=completion)
                client = SimpleNamespace(
                    chat=SimpleNamespace(
                        completions=SimpleNamespace(create=create)
                    )
                )
                with patch.dict(
                    os.environ, {"GROQ_API_KEY": "synthetic-test-key"}
                ):
                    if configured_value is None:
                        os.environ.pop("SOC_AI_STRICT_PRIVACY", None)
                    else:
                        os.environ["SOC_AI_STRICT_PRIVACY"] = configured_value
                    with patch("groq_service.Groq", return_value=client):
                        _generate(
                            "Host ws-23.corp.example user=alice; IP 192.168.4.8",
                            system_prompt=(
                                "URL https://srv.internal.local/a; IP 192.168.4.8"
                            ),
                        )

                messages = create.call_args.kwargs["messages"]
                for message in messages:
                    self.assertNotIn("192.168.4.8", message["content"])
                    self.assertIn("[NONPUBLIC_IP_", message["content"])
                if strict_enabled:
                    self.assertIn("[REDACTED_HOST]", messages[1]["content"])
                    self.assertIn("[REDACTED_USER]", messages[1]["content"])
                    self.assertIn("[REDACTED_URL]", messages[0]["content"])
                else:
                    self.assertIn("ws-23.corp.example", messages[1]["content"])
                    self.assertIn("user=alice", messages[1]["content"])
                    self.assertIn(
                        "https://srv.internal.local/a", messages[0]["content"]
                    )

    def test_provider_errors_return_safe_responses(self):
        with patch(
            "app.generate_investigation_report",
            side_effect=GroqUnavailable("private provider detail"),
        ):
            response = self.post_report()

        self.assertEqual(response.status_code, 503)
        self.assertNotIn(b"private provider detail", response.data)

    def test_unexpected_errors_return_safe_responses(self):
        with patch(
            "app.generate_investigation_report",
            side_effect=RuntimeError("private internal detail"),
        ):
            response = self.post_report()

        self.assertEqual(response.status_code, 500)
        self.assertNotIn(b"private internal detail", response.data)

    def test_report_prompt_requires_evidence_separation_and_uncertainty(self):
        provider_response = """## AI assessment (unverified)
Synthetic hypothesis.

## Unknowns and limitations
The supplied record is insufficient.

## Recommended investigation steps
Review related records.
"""
        with patch("groq_service._generate", return_value=provider_response) as generate:
            result = generate_investigation_report(
                {"rule": {"id": "1001"}}, "synthetic notes"
            )

        self.assertTrue(result.startswith("AI-GENERATED DRAFT — UNVERIFIED"))
        prompt = generate.call_args.args[0]
        system_prompt = generate.call_args.kwargs["system_prompt"]
        for heading in (
            "AI assessment (unverified)",
            "Unknowns and limitations",
            "Recommended investigation steps",
        ):
            self.assertIn(heading, prompt)
        self.assertIn("untrusted data", system_prompt)
        self.assertIn("invent events", system_prompt)

    def test_report_has_deterministic_evidence_and_analyst_placeholder(self):
        provider_response = """## AI assessment (unverified)
Synthetic hypothesis.

## Unknowns and limitations
Insufficient evidence.

## Recommended investigation steps
Check related records.
"""
        with patch("groq_service._generate", return_value=provider_response):
            report = generate_investigation_report(
                {"rule": {"id": "1001"}}, "synthetic note"
            )

        self.assertIn('Allowlisted record fields (JSON): {"rule": {"id": "1001"}}', report)
        self.assertIn("Not yet verified by an analyst.", report)

    def test_incomplete_provider_report_is_rejected(self):
        with patch("groq_service._generate", return_value="Incomplete draft"):
            with self.assertRaises(GroqUnavailable):
                generate_investigation_report({"rule": {"id": "1001"}})

if __name__ == "__main__":
    unittest.main()
