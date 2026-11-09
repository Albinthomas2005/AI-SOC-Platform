import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import app, configured_max_request_bytes


TOKEN = "retention-test-token"
ADMIN_HEADERS = {
    "Authorization": f"Bearer {TOKEN}", "X-SOC-User": "retention-admin",
}


class RetentionAndLimitsTests(unittest.TestCase):
    def setUp(self):
        import database

        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db_patch = patch.object(
            database, "DB_PATH", Path(self.temp.name) / "retention.db"
        )
        self.db_patch.start()
        self.addCleanup(self.db_patch.stop)
        self.env_patch = patch.dict(os.environ, {
            "SOC_AI_INTERNAL_TOKEN": TOKEN,
            "SOC_AI_ALERT_RETENTION_DAYS": "30",
            "SOC_AI_REPORT_RETENTION_DAYS": "60",
        })
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        database.init_db()
        database.set_soc_user_role("retention-admin", "admin", "2026-01-01T00:00:00Z")
        self.client = app.test_client()

    def insert_old_rows(self):
        import database

        database.add_alert("2000-01-01T00:00:00+00:00", "low", "synthetic", None)
        with database.closing(database.get_connection()) as connection, connection:
            connection.execute(
                "INSERT INTO wazuh_raw_alerts VALUES (?, ?, ?)",
                ("old-alert", "2000-01-01T00:00:00+00:00", "{}"),
            )
            connection.execute(
                """INSERT INTO hunting_reports
                   (hunt_id, user_id, question, hypothesis, query_json, mitre_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                ("old-hunt", "retention-admin", "question", "hypothesis", "{}", "[]", "2000-01-01T00:00:00+00:00"),
            )
            connection.execute(
                "INSERT INTO training_imported_cases VALUES (?, ?, ?, ?)",
                ("old-case", "retention-admin", "2000-01-01T00:00:00+00:00", "{}"),
            )
            connection.execute(
                """INSERT INTO training_attempts
                   (attempt_id, user_id, scenario_id, submitted_at, verdict, escalate,
                    mitre_ids_json, invalid_mitre_ids_json, report_text, time_spent,
                    score_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                ("old-attempt", "retention-admin", "scenario", "2000-01-01T00:00:00+00:00", "benign", 0, "[]", "[]", "old report", 1, "{}"),
            )
            connection.execute(
                """INSERT INTO training_unscored_attempts
                   (attempt_id, case_id, user_id, submitted_at, verdict, report_text,
                    time_spent) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                ("old-unscored", "old-case", "retention-admin", "2000-01-01T00:00:00+00:00", "benign", "old report", 1),
            )
        database.save_ai_analysis("a" * 32, "2000-01-01T00:00:00+00:00", "{}", "old report")

    def table_counts(self):
        import database

        with database.closing(database.get_connection()) as connection, connection:
            return {
                table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in (
                    "alerts", "wazuh_raw_alerts", "ai_analyses", "hunting_reports",
                    "training_imported_cases", "training_attempts",
                    "training_unscored_attempts",
                )
            }

    def test_retention_defaults_to_dry_run_then_purges_only_after_opt_in(self):
        self.insert_old_rows()
        preview = self.client.post(
            "/api/admin/retention/purge", json={}, headers=ADMIN_HEADERS
        )
        self.assertEqual(preview.status_code, 200, preview.get_json())
        preview_body = preview.get_json()
        self.assertTrue(preview_body["dry_run"])
        self.assertEqual(set(preview_body["counts"].values()), {1})
        self.assertEqual(set(self.table_counts().values()), {1})

        purge = self.client.post(
            "/api/admin/retention/purge", json={"dry_run": False}, headers=ADMIN_HEADERS
        )
        self.assertEqual(purge.status_code, 200)
        self.assertFalse(purge.get_json()["dry_run"])
        self.assertEqual(set(purge.get_json()["counts"].values()), {1})
        self.assertEqual(set(self.table_counts().values()), {0})

    def test_retention_endpoint_is_admin_only_and_validates_options(self):
        unauthenticated = self.client.post("/api/admin/retention/purge", json={})
        self.assertEqual(unauthenticated.status_code, 401)
        denied = self.client.post(
            "/api/admin/retention/purge", json={},
            headers={"Authorization": f"Bearer {TOKEN}", "X-SOC-User": "ordinary-user"},
        )
        self.assertEqual(denied.status_code, 403)
        malformed = self.client.post(
            "/api/admin/retention/purge", json={"dry_run": "false"}, headers=ADMIN_HEADERS
        )
        self.assertEqual(malformed.status_code, 400)

    def test_rate_limit_returns_429_after_configured_requests(self):
        import app as app_module

        app_module.RATE_LIMIT_BUCKETS.clear()
        self.addCleanup(app_module.RATE_LIMIT_BUCKETS.clear)
        with patch.dict(os.environ, {"SOC_AI_RATE_LIMIT_PER_MINUTE": "2"}):
            first = self.client.get("/training/scenarios", headers=ADMIN_HEADERS)
            second = self.client.get("/training/scenarios", headers=ADMIN_HEADERS)
            third = self.client.get("/training/scenarios", headers=ADMIN_HEADERS)
        self.assertEqual((first.status_code, second.status_code, third.status_code), (200, 200, 429))
        self.assertIn("rate limit", third.get_json()["error"].casefold())

    def test_request_body_size_limit_returns_413(self):
        original_limit = app.config["MAX_CONTENT_LENGTH"]
        app.config["MAX_CONTENT_LENGTH"] = 1024
        self.addCleanup(lambda: app.config.__setitem__("MAX_CONTENT_LENGTH", original_limit))
        response = self.client.post(
            "/api/incidents", data=b"{" + b" " * 2048 + b"}",
            content_type="application/json", headers=ADMIN_HEADERS,
        )
        self.assertEqual(response.status_code, 413)

    def test_request_size_limit_is_configurable_and_bounded(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(configured_max_request_bytes(), 1024 * 1024)
        with patch.dict(os.environ, {"SOC_AI_MAX_REQUEST_BYTES": "2097152"}):
            self.assertEqual(configured_max_request_bytes(), 2 * 1024 * 1024)
        with self.assertRaisesRegex(RuntimeError, "between 1024"):
            configured_max_request_bytes("512")


if __name__ == "__main__":
    unittest.main()
