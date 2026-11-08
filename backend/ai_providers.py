"""Provider adapters used by the backend without exposing provider details."""

import ipaddress
import json
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


class GroqProvider:
    def __init__(self, client):
        self.client = client

    def generate(self, request_params):
        response = self.client.chat.completions.create(**request_params)
        return response.choices[0].message.content


class OllamaProvider:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        parsed = urlsplit(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("OLLAMA_BASE_URL must be an HTTP(S) URL")
        try:
            is_loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            is_loopback = parsed.hostname.casefold() == "localhost"
        if not is_loopback:
            raise ValueError("OLLAMA_BASE_URL must point to localhost or a loopback IP")

    def generate(self, request_params):
        payload = {
            "model": request_params["model"],
            "messages": request_params["messages"],
            "stream": False,
            "options": {"temperature": request_params.get("temperature", 0.2)},
        }
        request = Request(
            f"{self.base_url}/api/chat",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=120) as response:
            result = json.loads(response.read().decode("utf-8"))
        message = result.get("message") if isinstance(result, dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str) or not content.strip():
            raise ValueError("Ollama returned an invalid chat response")
        return content
