import json
import os
import unittest
from unittest.mock import Mock, patch

from groq_service import _generate


class TestOllamaProvider(unittest.TestCase):
    def test_selected_ollama_provider_uses_mocked_loopback_endpoint(self):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = json.dumps(
            {"message": {"role": "assistant", "content": "Synthetic local result"}}
        ).encode("utf-8")
        with patch.dict(
            os.environ,
            {
                "SOC_AI_PROVIDER": "ollama",
                "OLLAMA_MODEL": "synthetic-model",
                "OLLAMA_BASE_URL": "http://127.0.0.1:11434",
            },
            clear=True,
        ), patch("ai_providers.urlopen", return_value=response) as urlopen, patch(
            "groq_service.Groq"
        ) as groq:
            result = _generate("Synthetic prompt")

        self.assertEqual(result, "Synthetic local result")
        groq.assert_not_called()
        request = urlopen.call_args.args[0]
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(request.full_url, "http://127.0.0.1:11434/api/chat")
        self.assertEqual(body["model"], "synthetic-model")
        self.assertFalse(body["stream"])
        self.assertEqual(body["messages"][1]["content"], "Synthetic prompt")

    def test_ollama_provider_rejects_non_loopback_endpoint(self):
        from ai_providers import OllamaProvider

        with self.assertRaisesRegex(ValueError, "localhost or a loopback IP"):
            OllamaProvider("http://ollama.internal:11434")


if __name__ == "__main__":
    unittest.main()
