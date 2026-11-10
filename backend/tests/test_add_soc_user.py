import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "add-soc-user.py"


class AddSocUserTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.database_path = Path(self.temp.name) / "soc-users.db"
        self.env = {**os.environ, "SOC_AI_DB_PATH": str(self.database_path)}
        self.env.pop("SOC_AI_ADMIN_USERS", None)

    def run_script(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            cwd=ROOT,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
        )

    def users(self):
        with sqlite3.connect(self.database_path) as connection:
            return connection.execute(
                "SELECT username, role FROM soc_users ORDER BY username"
            ).fetchall()

    def test_adds_and_updates_only_the_explicitly_named_user(self):
        added = self.run_script("mapped.analyst", "L2")
        self.assertEqual(added.returncode, 0, added.stderr)
        self.assertEqual(self.users(), [("mapped.analyst", "L2")])

        updated = self.run_script("mapped.analyst", "L3")
        self.assertEqual(updated.returncode, 0, updated.stderr)
        self.assertEqual(self.users(), [("mapped.analyst", "L3")])

    def test_rejects_invalid_username_role_and_missing_role(self):
        for args in (("bad username", "L2"), ("analyst", "root"), ("analyst",)):
            with self.subTest(args=args):
                result = self.run_script(*args)
                self.assertEqual(result.returncode, 2)
        self.assertFalse(self.database_path.exists())


if __name__ == "__main__":
    unittest.main()
