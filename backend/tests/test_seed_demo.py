import importlib.util
import json
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "seed-demo.py"
SPEC = importlib.util.spec_from_file_location("seed_demo", SCRIPT_PATH)
seed_demo = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(seed_demo)


class DemoSeedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db_path = Path(self.temp.name) / "demo.db"

    def test_populates_labeled_ssh_sudo_and_resolved_incident_in_temp_db(self):
        seed_demo.seed_demo(self.db_path)
        import database

        with patch.object(database, "DB_PATH", self.db_path):
            raw_alerts = database.get_raw_alerts(20)
            with closing(database.get_connection()) as connection:
                incident = connection.execute(
                    "SELECT incident_id, title, status, category FROM incidents"
                ).fetchone()
        self.assertEqual(len(raw_alerts), 4)
        alerts = [json.loads(row["raw_json"]) for row in raw_alerts]
        ssh_alerts = [a for a in alerts if a["rule"]["id"] == "5710"]
        self.assertEqual(len(ssh_alerts), 3)
        self.assertTrue(all(a["data"]["srcip"] == "203.0.113.50" for a in ssh_alerts))
        sudo = next(a for a in alerts if a["rule"]["id"] == "5402")
        self.assertEqual(sudo["data"]["dstuser"], "root")
        self.assertIn("DEMO", sudo["rule"]["description"])
        self.assertEqual(tuple(incident)[2:], ("Resolved", "demo"))
        self.assertIn("DEMO", incident["title"])

    def test_refuses_real_database_path_without_touching_it(self):
        import database

        real_path = Path(database.__file__).resolve().parent / "soc_alerts.db"
        with self.assertRaisesRegex(ValueError, "demo database"):
            seed_demo.seed_demo(real_path)

    def test_reset_replaces_only_the_demo_fixtures(self):
        seed_demo.seed_demo(self.db_path)
        seed_demo.seed_demo(self.db_path, reset=True)
        import database

        with patch.object(database, "DB_PATH", self.db_path):
            self.assertEqual(len(database.get_raw_alerts(20)), 4)


if __name__ == "__main__":
    unittest.main()
