import io
import json
import logging
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import database
import lab_uploads
from app import app


class LabUploadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.db_path = root / "platform-test.db"
        self.target = root / "wazuh-input.log"
        self.alerts = root / "alerts.json"
        self.env = patch.dict(os.environ, {
            "SOC_AI_DB_PATH": str(self.db_path),
            "SOC_AI_INTERNAL_TOKEN": "lab-test-token",
            "SOC_AI_INJECT_ENABLED": "true",
            "SOC_AI_INJECT_PATH": str(self.target),
            "SOC_AI_INJECT_ALLOWED_DIR": str(root),
            "WAZUH_ALERTS_FILE": str(self.alerts),
        }, clear=False)
        self.env.start()
        database.init_db()
        lab_uploads._counts.clear()
        database.set_soc_user_role("lab-analyst", "L1", "2026-01-01T00:00:00Z")
        database.set_soc_user_role("lab-admin", "admin", "2026-01-01T00:00:00Z")
        app.config["TESTING"] = True
        self.client = app.test_client()

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def headers(self, user="lab-analyst"):
        return {"Authorization": "Bearer lab-test-token", "X-SOC-User": user}

    def upload(self, data=b"Jan  1 00:00:00 host sshd[10]: Failed password for x from 192.0.2.1 port 22 ssh2\n"):
        return self.client.post("/api/lab/uploads", headers=self.headers(), data={
            "file": (io.BytesIO(data), "test.log"), "title": "test", "platform": "linux",
        }, content_type="multipart/form-data")

    def test_requires_auth_and_role_and_is_disabled_by_default(self):
        self.assertEqual(self.client.get("/api/lab/status").status_code, 401)
        with patch.dict(os.environ, {"SOC_AI_INJECT_ENABLED": "false"}):
            self.assertEqual(self.upload().status_code, 403)
        self.assertEqual(self.client.get("/api/lab/status", headers=self.headers("lab-admin")).status_code, 200)

    def test_timestamp_suffix_append_and_metadata(self):
        response = self.upload()
        self.assertEqual(response.status_code, 201, response.get_json())
        first = self.target.read_text().splitlines()
        self.assertRegex(first[0], r"^# SOCLAB-INJECT upload=[0-9a-f]{32}$")
        self.assertNotIn("SOCLAB-INJECT", first[1])
        self.assertNotIn("Jan  1 00:00:00", first[1])
        self.assertRegex(first[1], r"^[A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2} host")
        self.upload()
        self.assertEqual(len(self.target.read_text().splitlines()), 4)
        rows = self.client.get("/api/lab/uploads", headers=self.headers()).get_json()["uploads"]
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["id"], rows[0]["upload_id"])

    def test_valid_ssh_sample_json_upload_succeeds(self):
        content = (Path(__file__).parents[1] / "lab_samples" / "ssh_bruteforce.log").read_text()
        response = self.client.post("/api/lab/uploads", headers=self.headers(), json={
            "filename": "ssh_bruteforce.log", "content": content,
            "title": "SSH sample", "platform": "linux",
        })
        self.assertEqual(response.status_code, 201, response.get_json())

    def test_windows_upload_returns_specific_unsupported_reason(self):
        response = self.client.post("/api/lab/uploads", headers=self.headers(), json={
            "filename": "windows.log", "content": "2026-11-09T10:00:00Z host EventID=4625",
            "title": "Windows sample", "platform": "windows",
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], lab_uploads.WINDOWS_PLATFORM_ERROR)
        self.assertEqual(response.get_json()["message"], lab_uploads.WINDOWS_PLATFORM_ERROR)

    def test_read_confirmation_matches_recent_alert_location_and_upload_time(self):
        self.assertEqual(self.upload().status_code, 201)
        upload = self.client.get("/api/lab/uploads", headers=self.headers()).get_json()["uploads"][0]
        before_alert = self.client.get("/api/lab/status", headers=self.headers()).get_json()
        self.assertFalse(before_alert["wazuh_read_confirmed"])
        self.alerts.write_text(json.dumps({
            "timestamp": upload["uploaded_at"],
            "location": str(self.target),
            "full_log": "sshd: Failed password",
        }) + "\n")
        status = self.client.get("/api/lab/status", headers=self.headers()).get_json()
        self.assertTrue(status["wazuh_read_confirmed"], status["wazuh_read_reason"])

    def test_read_confirmation_includes_recent_diagnostic_script_uploads(self):
        response = self.client.post("/api/lab/uploads", headers=self.headers("upload-diagnostic"), json={
            "filename": "ssh_bruteforce.log", "content": "sshd: Failed password from 192.0.2.44\n",
            "title": "SSH upload diagnostic", "platform": "linux",
        })
        self.assertEqual(response.status_code, 201, response.get_json())
        upload = response.get_json()["upload"]
        self.alerts.write_text(json.dumps({
            "timestamp": upload["uploaded_at"],
            "location": str(self.target),
            "rule": {"id": "5710"},
        }) + "\n")
        status = self.client.get("/api/lab/status", headers=self.headers()).get_json()
        self.assertTrue(status["wazuh_read_confirmed"], status["wazuh_read_reason"])

    def test_upload_attempt_log_has_status_reason_and_id_without_content(self):
        secret_content = "synthetic-private-log-content"
        with self.assertLogs(logging.getLogger("app"), level="WARNING") as captured:
            response = self.client.post("/api/lab/uploads", headers=self.headers(), json={
                "filename": "windows.log", "content": secret_content,
                "title": "Windows sample", "platform": "windows",
            })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(len(captured.output), 1)
        log_line = " ".join(captured.output)
        self.assertIn("status=received", log_line)
        self.assertIn("reason=request_received", log_line)
        self.assertRegex(log_line, r"upload_id=[0-9a-f]{32}")
        self.assertNotIn(secret_content, log_line)
        self.assertNotIn("lab-test-token", log_line)

    def test_append_permission_error_returns_clear_500(self):
        with patch.object(lab_uploads, "_append", side_effect=PermissionError):
            response = self.upload()
        self.assertEqual(response.status_code, 500)
        self.assertIn("check backend service permissions", response.get_json()["message"])

    def test_rejects_binary_and_limits_but_redacts_public_ip(self):
        for value in (b"abc\x00def\n", b"\xff\xfe"):
            with self.subTest(value=value):
                self.assertEqual(self.upload(value).status_code, 400)
        public_ip = b"Jan  1 00:00:00 host sshd: Failed login from 8.8.8.8\n"
        self.assertEqual(self.upload(public_ip).status_code, 201)
        self.assertIn("198.51.100.10", self.target.read_text())
        self.assertNotIn("8.8.8.8", self.target.read_text())
        self.assertEqual(self.upload(b"x\n" * 2001).status_code, 400)
        self.assertEqual(self.upload(b"x" * (1024 * 1024 + 1)).status_code, 400)

    def test_documentation_ips_are_allowed(self):
        self.assertEqual(self.upload(b"Jan  1 00:00:00 host sshd: test from 198.51.100.4\n").status_code, 201)

    def test_rejects_symlink_target_and_path_escape(self):
        link = Path(self.temp.name) / "target-link"
        link.symlink_to(self.target)
        with patch.dict(os.environ, {"SOC_AI_INJECT_PATH": str(link)}):
            self.assertEqual(self.upload().status_code, 400)
        with patch.dict(os.environ, {"SOC_AI_INJECT_PATH": str(Path(self.temp.name).parent / "outside.log")}):
            self.assertEqual(self.upload().status_code, 400)

    def test_samples_and_delete_only_remove_platform_record(self):
        self.assertTrue(self.client.get("/api/lab/samples", headers=self.headers()).get_json()["samples"])
        response = self.client.post("/api/lab/samples/ssh_bruteforce.log", headers=self.headers())
        self.assertEqual(response.status_code, 201, response.get_json())
        content = self.target.read_text()
        upload_id = response.get_json()["upload"]["id"]
        deleted = self.client.delete(f"/api/lab/uploads/{upload_id}", headers=self.headers())
        self.assertTrue(deleted.get_json()["alerts_remain_in_wazuh"])
        self.assertEqual(self.target.read_text(), content)

    def test_delete_code_is_scoped_to_lab_records(self):
        source = (Path(__file__).parents[1] / "lab_uploads.py").read_text()
        self.assertIn('DELETE FROM lab_uploads WHERE upload_id = ?', source)
        self.assertNotRegex(source, r"\b(?:unlink|remove|rmtree)\s*\(")

    def test_rate_limit_is_three_uploads_per_user(self):
        for _ in range(3):
            self.assertEqual(self.upload().status_code, 201)
        self.assertEqual(self.upload().status_code, 429)


if __name__ == "__main__":
    unittest.main()
