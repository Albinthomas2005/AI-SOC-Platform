import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import app
from correlation import correlate_alerts, correlation_window_minutes


TOKEN = "correlation-test-token"
HEADERS = {"Authorization": f"Bearer {TOKEN}", "X-SOC-User": "correlation-analyst"}


def ssh_sequence():
    return [
        {
            "_id": "ssh-fail-1",
            "@timestamp": "2026-01-02T03:00:00Z",
            "agent": {"name": "ssh-host"},
            "data": {"srcuser": "svc-account", "srcip": "8.8.8.8"},
            "rule": {"id": "5710", "description": "SSH authentication failed"},
        },
        {
            "_id": "ssh-fail-2",
            "@timestamp": "2026-01-02T03:02:00Z",
            "agent": {"name": "ssh-host"},
            "data": {"srcuser": "svc-account", "srcip": "8.8.8.8"},
            "rule": {"id": "5710", "description": "SSH authentication failed"},
        },
        {
            "_id": "ssh-success",
            "@timestamp": "2026-01-02T03:04:00Z",
            "agent": {"name": "ssh-host"},
            "data": {"srcuser": "svc-account", "srcip": "8.8.8.8"},
            "rule": {"id": "5715", "description": "SSH authentication succeeded"},
        },
        {
            "_id": "sudo",
            "@timestamp": "2026-01-02T03:07:00Z",
            "agent": {"name": "ssh-host"},
            "data": {"dstuser": "svc-account"},
            "rule": {"id": "5402", "description": "User ran sudo"},
        },
    ]


class CorrelationApiTests(unittest.TestCase):
    def setUp(self):
        import database

        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db_patch = patch.object(
            database, "DB_PATH", Path(self.temp.name) / "correlation.db"
        )
        self.db_patch.start()
        self.addCleanup(self.db_patch.stop)
        database.init_db()
        database.set_soc_user_role("correlation-analyst", "L2", "2026-01-01T00:00:00Z")
        self.env_patch = patch.dict(os.environ, {"SOC_AI_INTERNAL_TOKEN": TOKEN})
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        self.client = app.test_client()

    def test_ssh_failures_success_and_sudo_form_one_timeline(self):
        with patch("app.summarize_correlation", return_value="Synthetic sequence summary") as summarize:
            response = self.client.post(
                "/api/correlations", json={"alerts": ssh_sequence()}, headers=HEADERS
            )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["summary"], "Synthetic sequence summary")
        groups = body["correlation"]["groups"]
        self.assertEqual(len(groups), 1)
        group = groups[0]
        self.assertEqual(
            group["alert_ids"], ["ssh-fail-1", "ssh-fail-2", "ssh-success", "sudo"]
        )
        self.assertEqual(
            [event["rule_ids"][0] for event in group["timeline"]],
            ["5710", "5710", "5715", "5402"],
        )
        self.assertEqual(
            {entity["type"] for entity in group["shared_entities"]},
            {"host", "user", "source_ip"},
        )
        self.assertEqual(len(group["timeline"]), 4)
        self.assertIn("timestamp", group["timeline"][0])
        summarize.assert_called_once_with(body["correlation"])

    def test_unrelated_alerts_are_not_grouped(self):
        alerts = ssh_sequence()[:2]
        alerts[1]["agent"]["name"] = "different-host"
        alerts[1]["data"]["srcuser"] = "different-user"
        alerts[1]["data"]["srcip"] = "1.1.1.1"
        result = correlate_alerts(alerts)
        self.assertEqual(result["groups"], [])

    def test_alerts_outside_window_are_not_grouped(self):
        alerts = ssh_sequence()[:2]
        alerts[1]["@timestamp"] = "2026-01-02T03:16:00Z"
        self.assertEqual(correlate_alerts(alerts)["groups"], [])

    def test_correlation_window_defaults_and_can_be_configured(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(correlation_window_minutes(), 15)
        with patch.dict(os.environ, {"SOC_AI_CORRELATION_WINDOW_MINUTES": "7"}):
            self.assertEqual(correlation_window_minutes(), 7)

    def test_summary_provider_receives_only_grouped_sanitized_data(self):
        from correlation import correlate_alerts
        from groq_service import summarize_correlation

        grouped = correlate_alerts(ssh_sequence())
        with patch("groq_service._generate", return_value="Synthetic summary") as generate:
            result = summarize_correlation(grouped)

        self.assertEqual(result, "Synthetic summary")
        prompt = generate.call_args.args[0]
        self.assertIn("ssh-fail-1", prompt)
        self.assertIn("5710", prompt)
        self.assertIn("[REDACTED_HOST]", prompt)
        self.assertIn("[REDACTED_USER]", prompt)
        self.assertIn("[REDACTED_PUBLIC_IP]", prompt)
        for private_value in ("ssh-host", "svc-account", "8.8.8.8"):
            self.assertNotIn(private_value, prompt)
        self.assertIn("deterministically grouped", prompt)

    def test_endpoint_requires_internal_authentication(self):
        response = self.client.post(
            "/api/correlations", json={"alerts": ssh_sequence()}
        )
        self.assertEqual(response.status_code, 401)

    def test_invalid_alert_timestamps_are_rejected(self):
        response = self.client.post(
            "/api/correlations",
            json={"alerts": [{"id": "missing-time", "rule": {"id": "1"}}]},
            headers=HEADERS,
        )
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
