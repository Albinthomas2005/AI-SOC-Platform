import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from app import run_app
import database


class TestAppRunConfiguration(unittest.TestCase):
    def test_default_host_and_port(self):
        with patch.dict(os.environ, {}, clear=True), patch("app.app.run") as run:
            run_app()

        run.assert_called_once_with(host="127.0.0.1", port=5000, debug=False)

    def test_custom_port_is_used(self):
        with patch.dict(os.environ, {"SOC_AI_PORT": "5123"}, clear=True), patch(
            "app.app.run"
        ) as run:
            run_app()

        run.assert_called_once_with(host="127.0.0.1", port=5123, debug=False)

    def test_invalid_port_is_rejected_before_server_starts(self):
        with patch.dict(os.environ, {"SOC_AI_PORT": "not-a-port"}, clear=True), patch(
            "app.app.run"
        ) as run:
            with self.assertRaisesRegex(SystemExit, "SOC_AI_PORT must be an integer"):
                run_app()

        run.assert_not_called()

    def test_non_loopback_host_is_refused_without_override(self):
        with patch.dict(
            os.environ, {"SOC_AI_HOST": "192.0.2.10"}, clear=True
        ), patch("app.app.run") as run:
            with self.assertRaisesRegex(SystemExit, "SOC_AI_HOST must be loopback"):
                run_app()

        run.assert_not_called()

    def test_database_path_environment_is_read_at_connection_time(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            demo_path = Path(temp_dir) / "demo.db"
            with patch.dict(os.environ, {"SOC_AI_DB_PATH": str(demo_path)}), patch(
                "database.sqlite3.connect", return_value=Mock()
            ) as connect:
                database.get_connection()
            connect.assert_called_once_with(demo_path)


if __name__ == "__main__":
    unittest.main()
