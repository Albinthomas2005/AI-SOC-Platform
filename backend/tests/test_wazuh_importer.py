import json
import os
import sqlite3
import stat
import tempfile
import unittest
from contextlib import closing
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import wazuh_importer as importer
import database


class TestImportAlertsInputPath(unittest.TestCase):
    def test_unset_path_exits_with_clear_message(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(
            SystemExit
        ) as error:
            importer.import_alerts()

        self.assertIn("WAZUH_ALERTS_FILE must be set", str(error.exception))

    def test_world_writable_file_is_refused(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            alerts_file = Path(temp_dir) / "alerts.jsonl"
            alerts_file.write_text("{}\n", encoding="utf-8")
            alerts_file.chmod(0o666)
            with patch.dict(
                os.environ, {"WAZUH_ALERTS_FILE": str(alerts_file)}
            ), self.assertRaises(SystemExit) as error:
                importer.import_alerts()

        self.assertIn("world-writable", str(error.exception))

    def test_normal_file_is_imported(self):
        event = {
            "id": "synthetic-alert-id",
            "timestamp": "2026-11-07T00:00:00Z",
            "rule": {"level": 8, "description": "Synthetic event"},
            "data": {"srcip": "192.0.2.10"},
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            alerts_file = Path(temp_dir) / "alerts.jsonl"
            alerts_file.write_text(json.dumps(event) + "\n", encoding="utf-8")
            alerts_file.chmod(0o600)
            database_path = Path(temp_dir) / "alerts.db"
            output = StringIO()

            with patch.dict(
                os.environ, {"WAZUH_ALERTS_FILE": str(alerts_file)}
            ), patch.object(importer, "DB_PATH", database_path), patch.object(
                database, "DB_PATH", database_path
            ), redirect_stdout(output):
                importer.import_alerts()

            with closing(sqlite3.connect(database_path)) as db, db:
                imported = db.execute(
                    "SELECT timestamp, severity, rule, source_ip FROM alerts"
                ).fetchone()

        self.assertEqual(
            imported,
            (
                "2026-11-07T00:00:00Z",
                "Medium",
                "Synthetic event",
                "192.0.2.10",
            ),
        )
        self.assertIn("Imported: 1", output.getvalue())


if __name__ == "__main__":
    unittest.main()
