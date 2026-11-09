import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import app


TOKEN = "incident-test-token"
HEADERS = {"Authorization": f"Bearer {TOKEN}", "X-SOC-User": "incident-analyst"}


class IncidentApiTests(unittest.TestCase):
    def setUp(self):
        import database

        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db_patch = patch.object(
            database, "DB_PATH", Path(self.temp.name) / "incidents.db"
        )
        self.db_patch.start()
        self.addCleanup(self.db_patch.stop)
        database.init_db()
        database.set_soc_user_role("incident-analyst", "L2", "2026-01-01T00:00:00Z")
        self.env_patch = patch.dict(os.environ, {"SOC_AI_INTERNAL_TOKEN": TOKEN})
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        self.client = app.test_client()

    def create_from_alert(self):
        response = self.client.post(
            "/api/incidents",
            json={
                "title": "Synthetic SSH investigation",
                "category": "authentication",
                "alerts": [{
                    "_id": "alert-ssh-1",
                    "@timestamp": "2026-01-02T03:00:00Z",
                    "rule": {"id": "5710", "description": "Failed SSH login"},
                    "data": {"srcip": "8.8.8.8", "password": "discard-me"},
                }],
            },
            headers=HEADERS,
        )
        self.assertEqual(response.status_code, 201, response.get_json())
        return response.get_json()["incident"]

    def test_create_incident_from_alerts_persists_evidence_and_timeline(self):
        incident = self.create_from_alert()
        self.assertEqual(incident["status"], "New")
        self.assertEqual(incident["category"], "authentication")
        self.assertEqual(len(incident["evidence"]), 1)
        self.assertEqual(incident["evidence"][0]["_id"], "alert-ssh-1")
        self.assertNotIn("discard-me", str(incident["evidence"]))
        self.assertEqual(incident["timeline"][0]["event_type"], "created")

        listed = self.client.get("/api/incidents", headers=HEADERS).get_json()["incidents"]
        self.assertEqual([item["incident_id"] for item in listed], [incident["incident_id"]])
        fetched = self.client.get(
            f"/api/incidents/{incident['incident_id']}", headers=HEADERS
        )
        self.assertEqual(fetched.status_code, 200)
        self.assertEqual(fetched.get_json()["incident"]["title"], "Synthetic SSH investigation")

    def test_create_incident_from_correlation_group(self):
        group = {
            "group_id": "correlation-1",
            "timeline": [
                {"alert_id": "a1", "timestamp": "2026-01-02T03:00:00Z", "rule_ids": ["5710"]},
                {"alert_id": "a2", "timestamp": "2026-01-02T03:02:00Z", "rule_ids": ["5715"]},
            ],
        }
        response = self.client.post(
            "/api/incidents", json={"correlation_group": group}, headers=HEADERS
        )
        self.assertEqual(response.status_code, 201)
        incident = response.get_json()["incident"]
        self.assertEqual(len(incident["evidence"]), 2)
        self.assertEqual(incident["evidence"][0]["alert_id"], "a1")

    def test_status_transitions_are_validated_and_logged(self):
        incident = self.create_from_alert()
        incident_id = incident["incident_id"]
        investigating = self.client.post(
            f"/api/incidents/{incident_id}/status",
            json={"status": "Investigating"},
            headers=HEADERS,
        )
        self.assertEqual(investigating.status_code, 200)
        invalid = self.client.post(
            f"/api/incidents/{incident_id}/status",
            json={"status": "New"}, headers=HEADERS,
        )
        self.assertEqual(invalid.status_code, 409)
        self.assertIn("Invalid status transition", invalid.get_json()["error"])

        contained = self.client.post(
            f"/api/incidents/{incident_id}/status",
            json={"status": "Contained"}, headers=HEADERS,
        )
        resolved = self.client.post(
            f"/api/incidents/{incident_id}/status",
            json={"status": "Resolved"}, headers=HEADERS,
        )
        closed = self.client.post(
            f"/api/incidents/{incident_id}/status",
            json={"status": "Closed"}, headers=HEADERS,
        )
        self.assertEqual((contained.status_code, resolved.status_code, closed.status_code), (200, 200, 200))
        reopen = self.client.post(
            f"/api/incidents/{incident_id}/status",
            json={"status": "Investigating"}, headers=HEADERS,
        )
        self.assertEqual(reopen.status_code, 409)
        final = self.client.get(
            f"/api/incidents/{incident_id}", headers=HEADERS
        ).get_json()["incident"]
        self.assertEqual(final["status"], "Closed")
        self.assertEqual(
            [event["event_type"] for event in final["timeline"]].count("status_changed"), 4
        )

    def test_assignment_notes_decisions_and_markdown_report(self):
        incident_id = self.create_from_alert()["incident_id"]
        assignment = self.client.post(
            f"/api/incidents/{incident_id}/assignment",
            json={"analyst": "analyst-two"},
            headers=HEADERS,
        )
        self.assertEqual(assignment.status_code, 200)
        self.assertEqual(assignment.get_json()["incident"]["assigned_analyst"], "analyst-two")

        note = self.client.post(
            f"/api/incidents/{incident_id}/notes",
            json={"note": "Reviewed the synthetic SSH evidence."},
            headers=HEADERS,
        )
        self.assertEqual(note.status_code, 201)
        decision = self.client.post(
            f"/api/incidents/{incident_id}/decisions",
            json={"decision": "Escalate to identity team", "rationale": "Successful login followed repeated failures."},
            headers=HEADERS,
        )
        self.assertEqual(decision.status_code, 201)

        report = self.client.get(
            f"/api/incidents/{incident_id}/report", headers=HEADERS
        )
        self.assertEqual(report.status_code, 200)
        markdown = report.get_json()["report"]
        self.assertIn("# Synthetic SSH investigation", markdown)
        self.assertIn("## Evidence", markdown)
        self.assertIn("## Analyst notes", markdown)
        self.assertIn("## Decision log", markdown)
        self.assertIn("Escalate to identity team", markdown)

    def test_invalid_incident_requests_are_rejected(self):
        no_source = self.client.post("/api/incidents", json={}, headers=HEADERS)
        malformed = self.client.post(
            "/api/incidents", json={"alerts": []}, headers=HEADERS
        )
        self.assertEqual(no_source.status_code, 400)
        self.assertEqual(malformed.status_code, 400)

    def test_every_incident_route_requires_authentication(self):
        import re

        routes = [rule for rule in app.url_map.iter_rules() if rule.rule.startswith("/api/incidents")]
        self.assertGreaterEqual(len(routes), 7)
        for route in routes:
            path = re.sub(r"<[^>]+>", "0" * 32, route.rule)
            methods = route.methods & {"GET", "POST"}
            for method in methods:
                with self.subTest(path=path, method=method):
                    response = self.client.open(path, method=method, json={})
                    self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
