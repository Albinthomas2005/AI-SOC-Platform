import os
import unittest
from unittest.mock import patch

from app import run_app


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

    def test_non_loopback_host_is_refused_without_override(self):
        with patch.dict(
            os.environ, {"SOC_AI_HOST": "192.0.2.10"}, clear=True
        ), patch("app.app.run") as run:
            with self.assertRaisesRegex(SystemExit, "SOC_AI_HOST must be loopback"):
                run_app()

        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
