import base64
import io
import json
import subprocess
import unittest
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch

import wazuh_groq_integration as integration


class TestSaveExplanation(unittest.TestCase):
    def test_uses_basic_auth_https_request_without_subprocess(self):
        fake_password = "synthetic-test-password"
        response_body = {
            "_index": "soc-ai-explanations",
            "_id": "synthetic-document-id",
            "result": "created",
        }
        mocked_response = MagicMock()
        mocked_response.__enter__.return_value = mocked_response
        mocked_response.read.return_value = json.dumps(response_body).encode()
        fake_context = object()

        with patch.object(
            integration, "PASSWORD_FILE"
        ) as password_file, patch(
            "urllib.request.urlopen", return_value=mocked_response
        ) as urlopen, patch(
            "ssl.create_default_context", return_value=fake_context
        ) as create_context, patch(
            "subprocess.run"
        ) as subprocess_run, redirect_stdout(io.StringIO()):
            password_file.read_text.return_value = fake_password
            integration.save_explanation(
                {"id": "synthetic-alert-id"}, "Synthetic explanation"
            )

        request = urlopen.call_args.args[0]
        expected_credentials = base64.b64encode(
            f"soc_ai_service:{fake_password}".encode("utf-8")
        ).decode("ascii")
        self.assertEqual(request.full_url, integration.INDEX_URL)
        self.assertEqual(
            request.get_header("Authorization"),
            f"Basic {expected_credentials}",
        )
        self.assertEqual(
            request.get_header("Content-type"), "application/json"
        )
        self.assertEqual(json.loads(request.data)["ai_explanation"], "Synthetic explanation")
        self.assertEqual(create_context.call_args.kwargs["cafile"], integration.CA_FILE)
        urlopen.assert_called_once_with(
            request, context=fake_context, timeout=30
        )
        subprocess_run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
