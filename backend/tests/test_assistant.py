import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from app import app


TOKEN = "assistant-test-token"


class AssistantApiTests(unittest.TestCase):
    def setUp(self):
        import database

        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db_patch = patch.object(
            database, "DB_PATH", Path(self.temp.name) / "assistant.db"
        )
        self.db_patch.start()
        self.addCleanup(self.db_patch.stop)
        self.env_patch = patch.dict(os.environ, {
            "SOC_AI_INTERNAL_TOKEN": TOKEN,
            "SOC_AI_PROVIDER": "groq",
            "GROQ_API_KEY": "synthetic-assistant-key",
        })
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        database.init_db()
        database.set_soc_user_role("assistant-l1", "L1", "2026-01-01T00:00:00Z")
        database.set_soc_user_role("assistant-l2", "L2", "2026-01-01T00:00:00Z")
        database.set_soc_user_role("assistant-l3", "L3", "2026-01-01T00:00:00Z")
        database.set_soc_user_role("assistant-admin", "admin", "2026-01-01T00:00:00Z")
        self.client = app.test_client()

    def headers(self, username):
        return {"Authorization": f"Bearer {TOKEN}", "X-SOC-User": username}

    def provider_client(self, content):
        from unittest.mock import Mock

        completion = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
        )
        create = Mock(return_value=completion)
        client = SimpleNamespace(
            chat=SimpleNamespace(completions=SimpleNamespace(create=create))
        )
        return client, create

    def create_report(self):
        import database

        report_id = "a" * 32
        database.save_ai_analysis(
            report_id,
            "2026-01-01T00:00:00+00:00",
            json.dumps({"rule": {"description": "Synthetic report alert"}}),
            "Synthetic report says email analyst@example.org; password=synthetic-secret; IP 8.8.8.8; Bearer synthetic-token-value.",
        )
        return report_id

    def create_incident(self):
        import database

        incident_id = "b" * 32
        with database.closing(database.get_connection()) as connection, connection:
            connection.execute(
                """INSERT INTO incidents
                   (incident_id, title, category, status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (incident_id, "Restricted L2 incident title", "auth", "New", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
            )
            connection.execute(
                "INSERT INTO incident_evidence (incident_id, ordinal, evidence_json) VALUES (?, ?, ?)",
                (incident_id, 0, json.dumps({"rule": {"description": "restricted evidence"}})),
            )
        return incident_id

    def test_l1_assistant_uses_reports_but_excludes_incidents(self):
        report_id = self.create_report()
        incident_id = self.create_incident()
        answer = f"The report documents a synthetic finding [report:{report_id}]."
        client, create = self.provider_client(answer)
        with patch("groq_service.Groq", return_value=client):
            response = self.client.post(
                "/api/assistant/chat",
                json={
                    "question": "What did the report say?",
                    "evidence": [
                        {"type": "report", "id": report_id},
                        {"type": "incident", "id": incident_id},
                    ],
                },
                headers=self.headers("assistant-l1"),
            )
        self.assertEqual(response.status_code, 200, response.get_json())
        body = response.get_json()
        self.assertFalse(body["refused"])
        self.assertEqual(body["citations"], [{"type": "report", "id": report_id}])
        prompt = create.call_args.kwargs["messages"][1]["content"]
        self.assertIn(report_id, prompt)
        self.assertNotIn("Restricted L2 incident title", prompt)

    def test_no_accessible_evidence_is_refused_without_provider_call(self):
        incident_id = self.create_incident()
        with patch("groq_service.Groq") as groq:
            response = self.client.post(
                "/api/assistant/chat",
                json={"question": "Summarize this incident", "evidence": [{"type": "incident", "id": incident_id}]},
                headers=self.headers("assistant-l1"),
            )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["refused"])
        self.assertIn("accessible evidence", response.get_json()["answer"])
        groq.assert_not_called()

    def test_provider_prompt_is_privacy_filtered_and_answer_must_cite_ids(self):
        report_id = self.create_report()
        client, create = self.provider_client(
            f"The report contains a synthetic indicator [report:{report_id}]."
        )
        with patch("groq_service.Groq", return_value=client):
            response = self.client.post(
                "/api/assistant/chat",
                json={"question": "Summarize the report", "evidence": [{"type": "report", "id": report_id}]},
                headers=self.headers("assistant-l1"),
            )
        self.assertEqual(response.status_code, 200)
        prompt = create.call_args.kwargs["messages"][1]["content"]
        for private_value in ("analyst@example.org", "synthetic-secret", "8.8.8.8", "synthetic-token-value"):
            self.assertNotIn(private_value, prompt)
        self.assertIn("[REDACTED_EMAIL]", prompt)
        self.assertIn("[REDACTED_PUBLIC_IP]", prompt)

        uncited, _create = self.provider_client("There was a synthetic finding.")
        with patch("groq_service.Groq", return_value=uncited):
            invalid = self.client.post(
                "/api/assistant/chat",
                json={"question": "Summarize the report", "evidence": [{"type": "report", "id": report_id}]},
                headers=self.headers("assistant-l1"),
            )
        self.assertEqual(invalid.status_code, 502)

    def test_hunt_reports_are_scoped_to_owner_even_for_l3(self):
        import database

        with database.closing(database.get_connection()) as connection, connection:
            connection.execute(
                """INSERT INTO hunting_reports
                   (hunt_id, user_id, question, hypothesis, query_json, mitre_json,
                    results_json, interpretation, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                ("c" * 32, "another-hunter", "q", "owner-only hypothesis", "{}", "[]", "[]", "owner-only report", "2026-01-01T00:00:00Z"),
            )
        with patch("groq_service.Groq") as groq:
            response = self.client.post(
                "/api/assistant/chat",
                json={"question": "What did the hunt find?", "evidence": [{"type": "hunt", "id": "c" * 32}]},
                headers=self.headers("assistant-l3"),
            )
        self.assertTrue(response.get_json()["refused"])
        groq.assert_not_called()

    def test_assistant_endpoint_requires_internal_auth(self):
        response = self.client.post(
            "/api/assistant/chat", json={"question": "q", "evidence": []}
        )
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
