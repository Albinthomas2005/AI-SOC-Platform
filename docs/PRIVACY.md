# Privacy filter behavior

The backend minimizes alert evidence to a fixed allowlist before either AI
endpoint sends it to Groq. The allowed paths are defined in
`backend/privacy_filter.py`: timestamps; rule ID, level, description, groups,
and MITRE ID/tactic/technique; decoder name; agent ID; source/destination IP
and port; protocol; action; authentication result; and the Windows event ID.
Only scalar values and bounded scalar arrays are retained. Caller-supplied
fields such as `full_log`, usernames, commands, and arbitrary nested data are
excluded unless a specific allowlisted path includes them.

## Values removed or transformed

The provider-boundary filter always:

- replaces email addresses with `[REDACTED_EMAIL]`;
- replaces bearer credentials and values following recognized secret labels
  such as `password`, `api_key`, `token`, or `authorization`;
- replaces public IPv4 and IPv6 addresses with `[REDACTED_PUBLIC_IP]`;
- pseudonymizes private, loopback, and link-local addresses with an opaque
  `[NONPUBLIC_IP_…]` value that remains consistent inside one request;
- handles common bracketed, scoped, mapped, encoded, integer, and hexadecimal
  IP forms, and replaces recognized malformed IP-like values.

The filter does not alter input objects in place. A new pseudonym context is
created per analysis request; pseudonyms are not meant to correlate data
between requests.

## Optional strict mode

Setting `SOC_AI_STRICT_PRIVACY=true` (exact lowercase) additionally masks
common URLs, fully qualified hostnames, MAC addresses, explicitly labeled
usernames/accounts, and absolute Unix or Windows path tokens. Strict mode can
remove useful investigative evidence and remains opt-in.

## What is sent to the provider

For alert analysis, the backend sends the minimized and sanitized alert as
prompt content along with fixed analysis instructions. For Generate Report, it
sends the minimized and sanitized alert plus the analyst notes after applying
the same request privacy context. The Wazuh Dashboard server obtains selected
alert evidence as the signed-in user; it does not send raw browser-supplied
alert documents as trusted evidence. The backend then independently reapplies
the allowlist and privacy filter.

The configured Groq API is a third-party service. Sanitization reduces some
disclosure, but does not make the request anonymous or guarantee that all
identifying details are removed. Alert descriptions, rule content, IDs,
timestamps, system context, and sanitized analyst notes may still identify an
organization, host, or person. Review what will be analyzed and use synthetic
data until the privacy behavior has been reviewed for your deployment.

## Known gaps

- Default mode does not mask hostnames, URLs, MAC addresses, usernames, or file
  paths as a whole.
- It does not recognize every obfuscation, encoding, secret format, or command
  output. Bare numbers are intentionally preserved to avoid rewriting rule
  IDs and ports.
- Text may include proprietary or personal context even after address
  redaction. Model output can repeat supplied values.
- The unit tests prove representative patterns, not complete anonymization.
- No live Groq request or real Wazuh data was used to validate this document.

Do not send regulated, confidential, or production data until the deployment's
data handling and third-party processing have been approved. Keep provider
credentials server-side and never put them in the dashboard browser or Git.
