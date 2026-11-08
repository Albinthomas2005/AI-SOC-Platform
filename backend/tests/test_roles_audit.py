import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import app


TOKEN = "roles-test-token"


class RolesAndAuditTests(unittest.TestCase):
    def setUp(self):
        import database

        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db_patch = patch.object(
            database, "DB_PATH", Path(self.temp.name) / "roles.db"
        )
        self.db_patch.start()
        self.addCleanup(self.db_patch.stop)
        self.env_patch = patch.dict(os.environ, {
            "SOC_AI_INTERNAL_TOKEN": TOKEN,
            "SOC_AI_ADMIN_USERS": "bootstrap-admin",
        })
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        database.init_db()
        for username, role in (
            ("test-l1", "L1"), ("test-l2", "L2"),
            ("test-l3", "L3"), ("bootstrap-admin", "admin"),
        ):
            database.set_soc_user_role(username, role, "2026-01-01T00:00:00Z")
        self.client = app.test_client()

    def headers(self, username):
        return {"Authorization": f"Bearer {TOKEN}", "X-SOC-User": username}

    def test_each_role_is_checked_across_every_route_group(self):
        import hunting

        query = {
            "index": "wazuh-alerts-4.x-*", "size": 1,
            "query": {"match": {"rule.id": "5710"}},
        }
        proposal = {
            "hypothesis": "Synthetic hypothesis.", "query": query, "mitre": [],
        }
        expected = {
            "training": {"L1": 200, "L2": 200, "L3": 200, "admin": 200},
            "correlation": {"L1": 403, "L2": 200, "L3": 200, "admin": 200},
            "incidents": {"L1": 403, "L2": 200, "L3": 200, "admin": 200},
            "threat_intel": {"L1": 403, "L2": 200, "L3": 200, "admin": 200},
            "hunting": {"L1": 403, "L2": 403, "L3": 201, "admin": 201},
            "admin": {"L1": 403, "L2": 403, "L3": 403, "admin": 200},
        }
        roles = {"L1": "test-l1", "L2": "test-l2", "L3": "test-l3", "admin": "bootstrap-admin"}
        with patch("hunting.generate_hunt_proposal", return_value=proposal):
            for role, username in roles.items():
                headers = self.headers(username)
                responses = {
                    "training": self.client.get("/training/scenarios", headers=headers),
                    "correlation": self.client.post("/api/correlations", json={"alerts": []}, headers=headers),
                    "incidents": self.client.get("/api/incidents", headers=headers),
                    "threat_intel": self.client.post("/api/threat-intel/lookup", json={"alert": {}}, headers=headers),
                    "hunting": self.client.post("/api/hunts/proposals", json={"question": "synthetic hunt"}, headers=headers),
                    "admin": self.client.get("/api/admin/audit", headers=headers),
                }
                for group, response in responses.items():
                    with self.subTest(role=role, group=group):
                        self.assertEqual(response.status_code, expected[group][role], response.get_json())

    def test_admin_can_change_roles_and_view_audit_but_entries_are_append_only(self):
        import database

        admin_headers = self.headers("bootstrap-admin")
        changed = self.client.put(
            "/api/admin/users/new-analyst/role",
            json={"role": "L2"}, headers=admin_headers,
        )
        self.assertEqual(changed.status_code, 200)
        self.assertEqual(database.get_soc_user_role("new-analyst"), "L2")
        forbidden = self.client.put(
            "/api/admin/users/new-analyst/role", json={"role": "admin"},
            headers=self.headers("test-l3"),
        )
        self.assertEqual(forbidden.status_code, 403)

        l1_headers = self.headers("test-l1")
        imported = self.client.post(
            "/training/imported-cases",
            json={"alert": {"rule": {"description": "Synthetic imported alert"}}},
            headers=l1_headers,
        )
        self.assertEqual(imported.status_code, 201)
        self.client.get("/training/progress", headers=l1_headers)

        l2_headers = self.headers("test-l2")
        created = self.client.post(
            "/api/incidents", json={"alerts": [{"_id": "alert-1", "rule": {"id": "5710"}}]},
            headers=l2_headers,
        )
        self.assertEqual(created.status_code, 201)
        incident_id = created.get_json()["incident"]["incident_id"]
        status = self.client.post(
            f"/api/incidents/{incident_id}/status", json={"status": "Investigating"},
            headers=l2_headers,
        )
        decision = self.client.post(
            f"/api/incidents/{incident_id}/decisions",
            json={"decision": "Escalate", "rationale": "Synthetic test"},
            headers=l2_headers,
        )
        self.assertEqual((status.status_code, decision.status_code), (200, 201))

        events = self.client.get("/api/admin/audit", headers=admin_headers).get_json()["events"]
        actions = {event["action"] for event in events}
        self.assertTrue({"role_changed", "import", "export", "status_changed", "decision"}.issubset(actions))
        with self.assertRaises(sqlite3.IntegrityError):
            with database.closing(database.get_connection()) as connection, connection:
                connection.execute("UPDATE audit_log SET action = 'tampered'")
        with self.assertRaises(sqlite3.IntegrityError):
            with database.closing(database.get_connection()) as connection, connection:
                connection.execute("DELETE FROM audit_log")

    def test_admin_route_requires_authentication(self):
        response = self.client.get("/api/admin/audit")
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
