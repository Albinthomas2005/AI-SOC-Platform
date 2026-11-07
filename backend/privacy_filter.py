import hashlib
import hmac
import ipaddress
import math
import re
import secrets
from urllib.parse import unquote

EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
IPV4_RE = re.compile(
    r"(?<![A-Za-z0-9_.])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9_.])"
)
IPV6_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])"
    r"(?:[0-9a-f_.:%-]*::[A-Za-z0-9_.:%-]*|"
    r"(?:[0-9a-f_.%-]*:){7}[A-Za-z0-9_.%-]*)"
    r"(?![A-Za-z0-9:])"
)
BRACKETED_IPV6_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])\[(?P<address>"
    r"(?:[0-9a-f_.:%-]*::[A-Za-z0-9_.:%-]*|"
    r"(?:[0-9a-f_.%-]*:){7}[A-Za-z0-9_.%-]*)"
    r")\](?![A-Za-z0-9])"
)
OVERLONG_IPV6_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9:])(?:\[(?:[A-Za-z0-9_.%-]*:){8,}"
    r"[A-Za-z0-9_.%-]*\]|(?:[A-Za-z0-9_.%-]*:){8,}"
    r"[A-Za-z0-9_.%-]*)(?![A-Za-z0-9:])"
)
ENCODED_ADDRESS_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:%[0-9a-f]{2}|[a-z0-9:.]){3,}"
    r"(?![A-Za-z0-9])"
)
LABELED_NUMERIC_IP_RE = re.compile(
    r"(?i)(?P<label>\b(?:srcip|dstip|source[_ ]ip|destination[_ ]ip|ip)"
    r"\b\s*(?:[:=]\s*|\s+))"
    r"(?P<value>0x[0-9a-f]{1,8}|\d{1,10})(?![A-Za-z0-9.])"
)
URL_NUMERIC_HOST_RE = re.compile(
    r"(?i)(?P<prefix>\bhttps?://)(?P<host>0x[0-9a-f]{1,8}|\d{1,10})"
    r"(?=:\d+(?:[/?#\s]|$)|[/?#\s]|$)"
)
CLOCK_RE = re.compile(r"^(\d{1,2}):(\d{2}):(\d{2})(?:\.\d+)?$")
BEARER_RE = re.compile(
    r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"
)
SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|password|passwd|secret|authorization)"
    r"\b(\s*[:=]\s*)([^\s,;]+)"
)
SENSITIVE_KEYS = re.compile(
    r"(?i)(password|passwd|token|secret|api[_-]?key|"
    r"authorization|credential|private[_-]?key)"
)
IP_FIELD_NAMES = {
    "srcip",
    "dstip",
    "src_ip",
    "dst_ip",
    "sourceip",
    "destinationip",
    "source_ip",
    "destination_ip",
    "ip",
}
MAC_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:"
    r"(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|"
    r"(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}"
    r")(?![A-Za-z0-9])"
)
URL_RE = re.compile(
    r"(?i)\b(?:https?|ftp|ssh|sftp|wss?|file)://[^\s<>\"']+"
)
HOSTNAME_RE = re.compile(
    r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})\b"
)
USERNAME_RE = re.compile(
    r"(?i)\b(user(?:name)?|account|login)(\s*[:=]\s*)[^\s,;]+"
)
UNIX_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9])/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+"
)
WINDOWS_PATH_RE = re.compile(r"(?i)\b[A-Z]:\\(?:[^\\\s]+\\)*[^\\\s]+")

REPORT_EVIDENCE_FIELDS = (
    "@timestamp",
    "timestamp",
    "rule.id",
    "rule.level",
    "rule.description",
    "rule.groups",
    "rule.mitre.id",
    "rule.mitre.tactic",
    "rule.mitre.technique",
    "decoder.name",
    "agent.id",
    "data.srcip",
    "data.dstip",
    "data.srcport",
    "data.dstport",
    "data.protocol",
    "data.action",
    "data.authentication_result",
    "data.win.system.eventID",
)


def new_privacy_context():
    """Create one in-memory pseudonym scope for a single analysis."""
    return {"salt": secrets.token_bytes(32), "addresses": {}}


def _is_clock(value):
    match = CLOCK_RE.fullmatch(value)
    if not match:
        return False
    hour, minute, second = (int(part) for part in match.groups()[:3])
    return hour < 24 and minute < 60 and second <= 60


def _mask_address(address, privacy_context, original=None):
    mapped_address = None
    if isinstance(address, ipaddress.IPv6Address):
        packed = address.packed
        if packed[:12] == (b"\x00" * 10 + b"\xff\xff"):
            mapped_address = ipaddress.IPv4Address(packed[12:])
    canonical_address = mapped_address or address
    if (
        canonical_address.is_private
        or canonical_address.is_loopback
        or canonical_address.is_link_local
    ):
        normalized = canonical_address.compressed.lower()
        addresses = privacy_context["addresses"]
        if normalized not in addresses:
            digest = hmac.new(
                privacy_context["salt"],
                normalized.encode("ascii"),
                hashlib.sha256,
            ).hexdigest()[:16]
            addresses[normalized] = f"[NONPUBLIC_IP_{digest}]"
        return addresses[normalized]
    if not canonical_address.is_global:
        return address.compressed if original is None else original
    return "[REDACTED_PUBLIC_IP]"


def _address_replacement(value, privacy_context, original=None):
    candidate = value.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return _mask_address(
        address,
        privacy_context,
        original=value if original is None else original,
    )


def _decode_repeatedly(value, rounds=5):
    decoded = value
    for _ in range(rounds):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return decoded


def _integer_ipv4(value):
    try:
        if value.lower().startswith("0x"):
            number = int(value, 16)
        elif value.isdecimal():
            number = int(value, 10)
        else:
            return None
        if not 0 <= number <= 0xFFFFFFFF:
            return None
        return ipaddress.IPv4Address(number)
    except (ValueError, TypeError):
        return None


def _sanitize_ip_field(value, privacy_context):
    if isinstance(value, int) and not isinstance(value, bool):
        address = _integer_ipv4(str(value))
        return _mask_address(address, privacy_context, original=value) if address else value
    if not isinstance(value, str):
        return value

    candidate = _decode_repeatedly(value.strip())
    address = _integer_ipv4(candidate)
    if address:
        return _mask_address(address, privacy_context, original=value)
    replacement = _address_replacement(
        candidate, privacy_context, original=value
    )
    if replacement is not None:
        return replacement
    if ":" in candidate or "." in candidate:
        return "[REDACTED_INVALID_IP]"
    return sanitize_text(value, privacy_context)


def _replace_encoded(match, privacy_context):
    encoded = match.group(0)
    if "%" not in encoded:
        return encoded
    decoded = _decode_repeatedly(encoded)
    replacement = _address_replacement(
        decoded, privacy_context, original=encoded
    )
    if replacement is not None:
        return replacement
    if decoded != encoded and "%" not in decoded:
        sanitized = sanitize_text(decoded, privacy_context)
        return sanitized if sanitized != decoded else encoded
    return encoded


def _replace_labeled_numeric(match, privacy_context):
    address = _integer_ipv4(match.group("value"))
    if address is None:
        return match.group(0)
    return match.group("label") + _mask_address(
        address, privacy_context, original=match.group("value")
    )


def _replace_url_numeric_host(match, privacy_context):
    address = _integer_ipv4(match.group("host"))
    if address is None:
        return match.group(0)
    return match.group("prefix") + _mask_address(
        address, privacy_context, original=match.group("host")
    )


def _replace_candidate(match, privacy_context):
    candidate = match.group(0)
    if _is_clock(candidate):
        return candidate
    replacement = _address_replacement(
        candidate, privacy_context, original=candidate
    )
    return replacement if replacement is not None else "[REDACTED_INVALID_IP]"


def _strict_sanitize_text(value):
    value = URL_RE.sub("[REDACTED_URL]", value)
    value = MAC_RE.sub("[REDACTED_MAC]", value)
    value = USERNAME_RE.sub(lambda m: m.group(1) + m.group(2) + "[REDACTED_USER]", value)
    value = WINDOWS_PATH_RE.sub("[REDACTED_PATH]", value)
    value = UNIX_PATH_RE.sub("[REDACTED_PATH]", value)
    return HOSTNAME_RE.sub("[REDACTED_HOST]", value)


def sanitize_text(value, privacy_context=None, strict=False):
    if privacy_context is None:
        privacy_context = new_privacy_context()
    value = EMAIL_RE.sub("[REDACTED_EMAIL]", value)
    value = BEARER_RE.sub("Bearer [REDACTED_TOKEN]", value)
    value = SECRET_RE.sub(
        lambda m: m.group(1) + m.group(2) + "[REDACTED_SECRET]",
        value,
    )
    value = ENCODED_ADDRESS_RE.sub(
        lambda match: _replace_encoded(match, privacy_context), value
    )
    value = URL_NUMERIC_HOST_RE.sub(
        lambda match: _replace_url_numeric_host(match, privacy_context), value
    )
    value = LABELED_NUMERIC_IP_RE.sub(
        lambda match: _replace_labeled_numeric(match, privacy_context), value
    )
    value = OVERLONG_IPV6_RE.sub(
        lambda match: "[REDACTED_INVALID_IP]", value
    )
    value = BRACKETED_IPV6_RE.sub(
        lambda match: _replace_candidate_address(
            match.group("address"), privacy_context
        ),
        value,
    )
    value = IPV6_RE.sub(lambda match: _replace_candidate(match, privacy_context), value)
    value = IPV4_RE.sub(lambda match: _replace_candidate(match, privacy_context), value)
    if strict:
        value = _strict_sanitize_text(value)
    return value


def _replace_candidate_address(value, privacy_context):
    replacement = _address_replacement(
        value, privacy_context, original=value
    )
    return replacement if replacement is not None else "[REDACTED_INVALID_IP]"


def sanitize_alert(value, parent_key="", privacy_context=None):
    """Recursively sanitize values in an alert dictionary."""
    if privacy_context is None:
        privacy_context = new_privacy_context()
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if SENSITIVE_KEYS.search(str(key)):
                cleaned[key] = "[REDACTED_SECRET]"
            else:
                cleaned[key] = sanitize_alert(item, str(key), privacy_context)
        return cleaned

    if isinstance(value, list):
        return [sanitize_alert(item, parent_key, privacy_context) for item in value]

    if parent_key.lower() in IP_FIELD_NAMES:
        return _sanitize_ip_field(value, privacy_context)

    if isinstance(value, str):
        return sanitize_text(value, privacy_context)

    return value


def minimize_report_evidence(alert, privacy_context=None):
    """Keep only scalar alert fields approved for external AI analysis."""
    if not isinstance(alert, dict):
        return {}

    minimized = {}
    for field in REPORT_EVIDENCE_FIELDS:
        value = alert
        for part in field.split("."):
            if not isinstance(value, dict) or part not in value:
                value = None
                break
            value = value[part]

        if isinstance(value, float) and not math.isfinite(value):
            continue
        if isinstance(value, (str, int, float, bool)):
            accepted = value
        elif isinstance(value, list):
            accepted = [
                item
                for item in value
                if isinstance(item, (str, int, float, bool))
                and not (isinstance(item, float) and not math.isfinite(item))
            ][:50]
            if not accepted:
                continue
        else:
            continue

        target = minimized
        parts = field.split(".")
        for part in parts[:-1]:
            target = target.setdefault(part, {})
        target[parts[-1]] = accepted

    return sanitize_alert(minimized, privacy_context=privacy_context)
