import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from app import app
from threat_intel import (
    AbuseIPDBAdapter,
    RateLimitExceeded,
    VirusTotalAdapter,
    cached_lookup,
    extract_iocs,
)


TOKEN = "threat-intel-test-token"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


class FakeHttpResponse:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit=-1):
        return self.payload


class ThreatIntelTests(unittest.TestCase):
    def setUp(self):
        import database

        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db_patch = patch.object(
            database, "DB_PATH", Path(self.temp.name) / "threat-intel.db"
        )
        self.db_patch.start()
        self.addCleanup(self.db_patch.stop)
        database.init_db()
        self.env_patch = patch.dict(os.environ, {"SOC_AI_INTERNAL_TOKEN": TOKEN})
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        self.client = app.test_client()

    def test_extracts_public_iocs_and_excludes_private_ips_and_hostnames(self):
        text = (
            "Contacted 8.8.8.8 and https://bad.example.org/malware?token=secret. "
            "Internal 10.0.0.8 node01.corp.local and srv.internal. "
            "Hash " + "a" * 64 + "."
        )
        iocs = extract_iocs(text)
        values = {(ioc["type"], ioc["value"]) for ioc in iocs}
        self.assertIn(("ip", "8.8.8.8"), values)
        self.assertIn(("domain", "bad.example.org"), values)
        self.assertIn(("url", "https://bad.example.org/malware"), values)
        self.assertIn(("hash", "a" * 64), values)
        for forbidden in ("10.0.0.8", "node01.corp.local", "srv.internal", "secret"):
            self.assertNotIn(forbidden, str(iocs))

    def test_alert_extraction_skips_secret_and_hostname_fields(self):
        iocs = extract_iocs({
            "agent": {"name": "build-server.example.org"},
            "password": "bad-password.example.net",
            "data": {
                "srcip": "192.168.1.4",
                "description": "Public indicator https://ioc.example.org/check",
            },
        })
        serialized = str(iocs)
        self.assertIn("ioc.example.org", serialized)
        self.assertNotIn("build-server", serialized)
        self.assertNotIn("bad-password", serialized)
        self.assertNotIn("192.168.1.4", serialized)

    def test_virustotal_and_abuseipdb_adapters_use_mocked_http(self):
        vt_open = Mock(return_value=FakeHttpResponse({"data": {"id": "8.8.8.8", "attributes": {"reputation": 4}}}))
        with patch("threat_intel.urlopen", vt_open):
            vt = VirusTotalAdapter("synthetic-vt-key")
            result = vt.lookup({"type": "ip", "value": "8.8.8.8"})
        self.assertEqual(result["attributes"]["reputation"], 4)
        vt_request = vt_open.call_args.args[0]
        self.assertEqual(vt_request.get_header("X-apikey"), "synthetic-vt-key")
        self.assertTrue(vt_request.full_url.endswith("/ip_addresses/8.8.8.8"))

        abuse_open = Mock(return_value=FakeHttpResponse({"data": {"ipAddress": "8.8.8.8", "abuseConfidenceScore": 0}}))
        with patch("threat_intel.urlopen", abuse_open):
            abuse = AbuseIPDBAdapter("synthetic-abuse-key")
            result = abuse.lookup({"type": "ip", "value": "8.8.8.8"})
        self.assertEqual(result["abuseConfidenceScore"], 0)
        abuse_request = abuse_open.call_args.args[0]
        self.assertEqual(abuse_request.get_header("Key"), "synthetic-abuse-key")
        self.assertIn("ipAddress=8.8.8.8", abuse_request.full_url)

    def test_sqlite_cache_avoids_repeated_http_and_enforces_rate_limit(self):
        provider = Mock()
        provider.name = "mock-provider"
        provider.lookup.return_value = {"reputation": 1}
        with patch.dict(os.environ, {
            "SOC_AI_THREAT_INTEL_CACHE_TTL": "3600",
            "SOC_AI_THREAT_INTEL_RATE_LIMIT_PER_MINUTE": "1",
        }):
            result, cached = cached_lookup(provider, {"type": "ip", "value": "8.8.8.8"}, now=120)
            same, cached_again = cached_lookup(provider, {"type": "ip", "value": "8.8.8.8"}, now=121)
            self.assertEqual(result, same)
            self.assertFalse(cached)
            self.assertTrue(cached_again)
            with self.assertRaises(RateLimitExceeded):
                cached_lookup(provider, {"type": "ip", "value": "1.1.1.1"}, now=122)
        provider.lookup.assert_called_once()

    def test_summary_only_receives_returned_data_and_marks_empty_provider(self):
        from threat_intel import summarize_threat_intel

        results = [
            {"provider": "virustotal", "ioc": {"value": "not-returned"}, "status": "ok", "data": {"reputation": 1}},
            {"provider": "abuseipdb", "ioc": {"value": "another-ioc"}, "status": "no_data", "data": None},
        ]
        with patch("groq_service._generate", return_value="VT returned low reputation; no data from AbuseIPDB") as generate:
            summary = summarize_threat_intel(results)
        self.assertIn("no data", summary.casefold())
        prompt = generate.call_args.args[0]
        self.assertIn("reputation", prompt)
        self.assertIn("abuseipdb", prompt)
        self.assertNotIn("not-returned", prompt)
        self.assertNotIn("another-ioc", prompt)

    def test_empty_provider_results_return_no_data_without_ai(self):
        from threat_intel import summarize_threat_intel

        with patch("groq_service._generate") as generate:
            result = summarize_threat_intel([
                {"provider": "virustotal", "status": "no_data", "data": None}
            ])
        self.assertIn("no data", result.casefold())
        generate.assert_not_called()

    def test_lookup_endpoint_requires_auth_and_filters_private_iocs(self):
        unauthenticated = self.client.post(
            "/api/threat-intel/lookup", json={"alert": {"data": {"srcip": "8.8.8.8"}}}
        )
        self.assertEqual(unauthenticated.status_code, 401)

        with patch("app.lookup_iocs", return_value=[]) as lookup:
            response = self.client.post(
                "/api/threat-intel/lookup",
                json={"alert": {
                    "agent": {"name": "host01.corp.local"},
                    "data": {"srcip": "10.0.0.4", "description": "8.8.8.8"},
                }},
                headers=HEADERS,
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(lookup.call_args.args[0], [{"type": "ip", "value": "8.8.8.8"}])
        self.assertIn("no data", response.get_json()["summary"].casefold())


if __name__ == "__main__":
    unittest.main()
