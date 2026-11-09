import io
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
        self.env = patch.dict(os.environ, {
            "SOC_AI_DB_PATH": str(self.db_path),
            "SOC_AI_INTERNAL_TOKEN": "lab-test-token",
            "SOC_AI_INJECT_ENABLED": "true",
            "SOC_AI_INJECT_PATH": str(self.target),
            "SOC_AI_INJECT_ALLOWED_DIR": str(root),
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
        first = self.target.read_text()
        self.assertIn("SOCLAB-INJECT upload=", first)
        self.assertNotIn("Jan  1 00:00:00", first)
        self.assertRegex(first, r"^[A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2} host")
        self.upload()
        self.assertEqual(len(self.target.read_text().splitlines()), 2)
        rows = self.client.get("/api/lab/uploads", headers=self.headers()).get_json()["uploads"]
        self.assertEqual(len(rows), 2)

    def test_rejects_binary_null_public_ip_and_limits(self):
        for value in (b"abc\x00def\n", b"\xff\xfe", b"GET / from 8.8.8.8\n"):
            with self.subTest(value=value):
                self.assertEqual(self.upload(value).status_code, 400)
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
