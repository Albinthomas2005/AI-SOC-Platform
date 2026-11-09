"""IOC extraction and cached VirusTotal/AbuseIPDB lookup adapters."""

import base64
import ipaddress
import json
import os
import re
import time
from contextlib import closing
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from database import get_connection
from privacy_filter import select_ai_alert_fields


IPV4_CANDIDATE = re.compile(r"(?<![A-Za-z0-9_.])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9_.])")
IPV6_CANDIDATE = re.compile(r"(?i)(?<![A-Za-z0-9:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![A-Za-z0-9:])")
DOMAIN_CANDIDATE = re.compile(
    r"(?i)(?<![@A-Za-z0-9_-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}(?![A-Za-z0-9_-])"
)
URL_CANDIDATE = re.compile(r"(?i)\bhttps?://[^\s<>\"']+")
HASH_CANDIDATE = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![0-9a-f])")
PRIVATE_SUFFIXES = {
    ".local", ".localhost", ".internal", ".lan", ".home", ".corp",
    ".test", ".example", ".invalid", ".onion",
}
MAX_LOOKUP_RESPONSE_BYTES = 256 * 1024
DEFAULT_CACHE_TTL_SECONDS = 3600
DEFAULT_PROVIDER_LIMIT_PER_MINUTE = 60


class RateLimitExceeded(Exception):
    """Raised when one threat-intel provider exceeds its configured limit."""


def _is_public_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global


def _is_public_domain(value):
    domain = value.rstrip(".").casefold()
    return (
        len(domain) <= 253
        and "." in domain
        and not domain.endswith(tuple(PRIVATE_SUFFIXES))
        and all(1 <= len(part) <= 63 for part in domain.split("."))
    )


def _canonical_url(value):
    candidate = value.rstrip(".,;:!?)]}")
    try:
        parsed = urlsplit(candidate)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not host:
        return None
    if not (_is_public_ip(host) or _is_public_domain(host)):
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    if port is not None and not 1 <= port <= 65535:
        return None
    # Query strings and fragments commonly carry session tokens or personal data.
    path = parsed.path or "/"
    if any(len(part) > 64 for part in path.split("/")):
        return None
    netloc = host.lower() + (f":{port}" if port is not None else "")
    return urlunsplit((parsed.scheme.lower(), netloc, path, "", ""))


def extract_iocs(value):
    """Extract deduplicated public IOCs; internal addresses and hostnames are excluded."""
    def safe_text(item, key=""):
        if re.search(r"(?i)(password|passwd|token|secret|api[_-]?key|authorization|credential|private[_-]?key)", key):
            return ""
        if re.search(r"(?i)^(?:host|hostname|agent|agent\.name)$", key):
            return ""
        if isinstance(item, dict):
            return " ".join(
                safe_text(child, str(child_key))
                for child_key, child in item.items()
                if str(child_key).casefold() != "full_log"
            )
        if isinstance(item, (list, tuple)):
            return " ".join(safe_text(child, key) for child in item)
        if isinstance(item, (str, int, float)):
            return str(item)
        return ""

    if isinstance(value, dict):
        value = select_ai_alert_fields(value)
    text = safe_text(value) if not isinstance(value, str) else value
    indicators = {}

    for match in URL_CANDIDATE.finditer(text):
        canonical = _canonical_url(match.group(0))
        if canonical:
            indicators[("url", canonical.casefold())] = {"type": "url", "value": canonical}

    candidates = list(IPV4_CANDIDATE.finditer(text)) + list(IPV6_CANDIDATE.finditer(text))
    for match in candidates:
        value = match.group(0)
        if _is_public_ip(value):
            canonical = ipaddress.ip_address(value).compressed
            indicators[("ip", canonical)] = {"type": "ip", "value": canonical}

    for match in DOMAIN_CANDIDATE.finditer(text):
        domain = match.group(0).rstrip(".").casefold()
        if _is_public_domain(domain):
            indicators[("domain", domain)] = {"type": "domain", "value": domain}

    for match in HASH_CANDIDATE.finditer(text):
        digest = match.group(0).lower()
        indicators[("hash", digest)] = {"type": "hash", "value": digest}

    return sorted(indicators.values(), key=lambda item: (item["type"], item["value"]))


class ThreatIntelProvider:
    name = "provider"

    def lookup(self, ioc):
        raise NotImplementedError


class VirusTotalAdapter(ThreatIntelProvider):
    name = "virustotal"
    base_url = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key, http_open=None):
        self.api_key = api_key
        self.http_open = http_open or urlopen

    def _resource_path(self, ioc):
        kind = ioc["type"]
        value = ioc["value"]
        if kind == "url":
            value = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")
            return f"urls/{value}"
        if kind == "ip":
            return f"ip_addresses/{quote(value, safe=':.')}"
        if kind == "domain":
            return f"domains/{quote(value, safe='.-')}"
        if kind == "hash":
            return f"files/{quote(value, safe='')}"
        raise ValueError("Unsupported IOC type")

    def lookup(self, ioc):
        request = Request(
            f"{self.base_url}/{self._resource_path(ioc)}",
            headers={"x-apikey": self.api_key, "Accept": "application/json"},
        )
        with self.http_open(request, timeout=10) as response:
            payload = response.read(MAX_LOOKUP_RESPONSE_BYTES + 1)
        if len(payload) > MAX_LOOKUP_RESPONSE_BYTES:
            raise ValueError("VirusTotal response exceeded the size limit")
        parsed = json.loads(payload.decode("utf-8"))
        data = parsed.get("data") if isinstance(parsed, dict) else None
        return data if isinstance(data, dict) else None


class AbuseIPDBAdapter(ThreatIntelProvider):
    name = "abuseipdb"
    endpoint = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key, http_open=None):
        self.api_key = api_key
        self.http_open = http_open or urlopen

    def lookup(self, ioc):
        if ioc["type"] != "ip" or not _is_public_ip(ioc["value"]):
            return None
        query = urlencode({"ipAddress": ioc["value"], "maxAgeInDays": 90})
        request = Request(
            f"{self.endpoint}?{query}",
            headers={"Key": self.api_key, "Accept": "application/json"},
        )
        with self.http_open(request, timeout=10) as response:
            payload = response.read(MAX_LOOKUP_RESPONSE_BYTES + 1)
        if len(payload) > MAX_LOOKUP_RESPONSE_BYTES:
            raise ValueError("AbuseIPDB response exceeded the size limit")
        parsed = json.loads(payload.decode("utf-8"))
        data = parsed.get("data") if isinstance(parsed, dict) else None
        return data if isinstance(data, dict) else None


def cached_lookup(provider, ioc, now=None):
    """Return a cached lookup or perform a rate-limited adapter request."""
    now = int(time.time() if now is None else now)
    try:
        ttl = max(0, int(os.environ.get("SOC_AI_THREAT_INTEL_CACHE_TTL", DEFAULT_CACHE_TTL_SECONDS)))
        rate_limit = max(1, int(os.environ.get(
            "SOC_AI_THREAT_INTEL_RATE_LIMIT_PER_MINUTE", DEFAULT_PROVIDER_LIMIT_PER_MINUTE
        )))
    except ValueError:
        raise ValueError("Threat-intel cache TTL and rate limit must be integers") from None

    with closing(get_connection()) as connection, connection:
        row = connection.execute(
            """SELECT cached_at, response_json FROM threat_intel_cache
               WHERE provider = ? AND ioc_type = ? AND ioc_value = ?""",
            (provider.name, ioc["type"], ioc["value"]),
        ).fetchone()
        if row and now - row["cached_at"] <= ttl:
            return json.loads(row["response_json"]), True

        window_start = now // 60 * 60
        count_row = connection.execute(
            """SELECT request_count FROM threat_intel_rate_limit
               WHERE provider = ? AND window_start = ?""",
            (provider.name, window_start),
        ).fetchone()
        if count_row and count_row["request_count"] >= rate_limit:
            raise RateLimitExceeded(f"{provider.name} rate limit exceeded")
        connection.execute(
            """INSERT INTO threat_intel_rate_limit
               (provider, window_start, request_count) VALUES (?, ?, 1)
               ON CONFLICT(provider, window_start) DO UPDATE
               SET request_count = request_count + 1""",
            (provider.name, window_start),
        )

    result = provider.lookup(ioc)
    with closing(get_connection()) as connection, connection:
        connection.execute(
            """INSERT INTO threat_intel_cache
               (provider, ioc_type, ioc_value, cached_at, response_json)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(provider, ioc_type, ioc_value) DO UPDATE SET
                 cached_at = excluded.cached_at,
                 response_json = excluded.response_json""",
            (provider.name, ioc["type"], ioc["value"], now, json.dumps(result)),
        )
    return result, False


def lookup_iocs(iocs, env=None):
    """Query configured providers; credentials are read only from environment."""
    env = os.environ if env is None else env
    configured = []
    if env.get("VIRUSTOTAL_API_KEY"):
        configured.append(VirusTotalAdapter(env["VIRUSTOTAL_API_KEY"]))
    if env.get("ABUSEIPDB_API_KEY"):
        configured.append(AbuseIPDBAdapter(env["ABUSEIPDB_API_KEY"]))

    results = []
    for ioc in iocs:
        for provider in configured:
            if provider.name == "abuseipdb" and ioc["type"] != "ip":
                continue
            try:
                data, cached = cached_lookup(provider, ioc)
            except RateLimitExceeded:
                raise
            except (HTTPError, URLError, TimeoutError, ValueError, json.JSONDecodeError):
                results.append({
                    "provider": provider.name,
                    "ioc": ioc,
                    "status": "error",
                    "data": None,
                })
                continue
            results.append({
                "provider": provider.name,
                "ioc": ioc,
                "status": "ok" if data else "no_data",
                "cached": cached,
                "data": data,
            })
    return results


def summarize_threat_intel(results):
    """Summarize only provider-returned records; use a literal no-data response otherwise."""
    returned_data = [
        {"provider": result["provider"], "data": result["data"]}
        for result in results
        if isinstance(result.get("data"), dict) and result["data"]
    ]
    if not returned_data:
        return "No data was returned by the configured threat-intelligence providers."
    from groq_service import _generate

    from privacy_filter import new_privacy_context, sanitize_text

    no_data_providers = sorted({
        result.get("provider") for result in results
        if result.get("status") == "no_data" and result.get("provider")
    })
    prompt = (
        "Summarize only these returned threat-intelligence records. Do not infer "
        "findings absent from the returned data. Explicitly state 'no data' for "
        "each provider listed as empty.\n"
        + json.dumps({
            "returned_data": returned_data,
            "providers_with_no_data": no_data_providers,
        }, ensure_ascii=False)
    )
    return _generate(sanitize_text(prompt, new_privacy_context())).strip()
