# SOC AI Alert Analyzer

An educational SOC home lab using Wazuh, Python, Groq, privacy filtering, and OpenSearch.

## Workflow

1. Receive or select a Wazuh-style security alert.
2. Sanitize selected sensitive values before external AI analysis.
3. Generate an AI-assisted explanation for analyst review.
4. Store the explanation and sanitized alert in a dedicated OpenSearch index.
5. Review stored results and validate findings manually.

## Features

- Synthetic-alert analysis with Groq
- Privacy-filtering helpers and unit tests
- OpenSearch indexing over HTTPS
- Separate reader and writer role examples
- Initial Wazuh alert importer and SQLite storage
- GitHub Actions workflow for Python unit tests

## Requirements

- Python 3.10 or newer
- Access to a Groq API key for AI analysis
- OpenSearch configured for the integration test
- Wazuh is needed for the full SIEM lab, but basic unit tests can run without a Wazuh server

## Local setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` locally and set your own `GROQ_API_KEY`. Never commit the real `.env` file. OpenSearch connection settings and credentials must be configured locally according to your deployment and the integration script.

The optional alert importer reads newline-delimited Wazuh JSON from the path in
`WAZUH_ALERTS_FILE`. Set it in the ignored local `.env` file to an authorized
alerts file. The importer refuses files with the world-writable permission bit.

## Internal AI analysis API

The provider defaults to Groq. To select local Ollama, set
`SOC_AI_PROVIDER=ollama`, `OLLAMA_BASE_URL=http://127.0.0.1:11434`, and
`OLLAMA_MODEL` to a model already installed in your local Ollama instance.
The backend accepts only `localhost` or loopback IPs for `OLLAMA_BASE_URL`.
Ollama requests are sent to `/api/chat`; the model must support the chat
endpoint. No provider credentials are required for this local option. This
adapter is covered by mocked tests; a real Ollama model has not been run here.

The Flask service exposes token-protected application endpoints. `POST /api/ai/analyze-alert`
accepts a Wazuh alert for trusted services that need an AI explanation. It requires a bearer token in the
`SOC_AI_INTERNAL_TOKEN` environment variable, accepts a JSON object containing
an `alert` object, sanitizes the alert before analysis, and returns JSON. The
endpoint shares the app's 1 MiB request-size limit and is not intended for
public exposure. The included Flask runner binds to `127.0.0.1`.

The development runner reads optional `SOC_AI_HOST` and `SOC_AI_PORT` settings
from `.env`, defaulting to `127.0.0.1` and `5000`. It accepts `127.0.0.1`,
`localhost`, and `::1` by default. Binding another host is refused unless
`SOC_AI_ALLOW_NON_LOOPBACK=true` is explicitly configured; exposing the service
outside loopback requires separate network controls.

The trusted Wazuh Dashboard server can call `POST /api/ai/generate-report`.
It requires the same bearer token and accepts a
selected record reference, a minimized alert, and optional analyst context.
The JSON request fields are `evidence.index`, `evidence.id`,
`evidence.alert`, and optional `analyst_notes`, for example:

```json
{
  "evidence": {
    "index": "wazuh-alerts-4.x-2026.10.25",
    "id": "<selected-document-id>",
    "alert": {"rule": {"id": "1001"}}
  },
  "analyst_notes": "Optional context from the analyst"
}
```

Requests are limited to 256 KiB and notes to 4,000 characters. The index must
match `wazuh-alerts-4.x-*` and document IDs are limited to 512 UTF-8 bytes.
The Wazuh controller retrieves the record as the signed-in user before making
this request; browser-supplied alert contents are not used as evidence. The
backend re-applies an evidence allowlist and privacy filtering before sending
the request to Groq. Report drafts are labeled AI-generated and unverified,
are not saved by this endpoint, and do not include related-log searches.
Analyst-edited Markdown export is performed in the dashboard browser; keep the
exported file in an approved case-management location if it must be retained.
There are no form-based analysis, report-improvement, or report-export routes.
All three application endpoints require the internal bearer token.

`POST /api/ai/analysis/<analysis_id>/decision` records `approved`, `edited`,
or `rejected` for an existing analysis. An optional note and decision timestamp
are saved with the sanitized evidence and original AI draft in the local
SQLite database. `edited` decisions also store the revised text without
overwriting the original draft. This endpoint is intended only for the
authenticated Dashboard server, which proxies the signed-in analyst's choice.

The default provider is Groq. For a local Ollama instance, set
`SOC_AI_PROVIDER=ollama`, `OLLAMA_BASE_URL` to a localhost or loopback URL, and
`OLLAMA_MODEL` to a model already installed locally. Ollama requests use
`/api/chat`; the adapter has mocked tests but has not been tested against a
running Ollama service.

Generate a strong token locally with:

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
```

Set the generated value as `SOC_AI_INTERNAL_TOKEN` in the ignored local `.env`
file (or the service's protected environment configuration). Configure the
same value securely in any trusted caller. Do not commit, log, or share the
token. Keep `.env.example` as a placeholder only.

## Run tests

```bash
python -m unittest discover -s tests -v
```

GitHub Actions runs the same unit-test command on pushes and pull requests to `main`.

With the backend running and `SOC_AI_INTERNAL_TOKEN` set in the ignored
`backend/.env`, run `./scripts/smoke_test.sh` from this directory. It reads the
port from `SOC_AI_PORT`, defaulting to `5000`; an optional positional port can
override it. The script checks that a request
without a token receives 401 and that the synthetic alert request returns
`ok: true`; it prints only PASS/FAIL and status information, never the token or
Groq key.

## Synthetic alert integration test

After configuring the Groq API key, OpenSearch URL, TLS certificate, and least-privilege OpenSearch credentials for your local environment, run:

```bash
python3 wazuh_groq_integration.py synthetic_alert.json
```

Do not run this integration test until the local OpenSearch settings are configured and you have confirmed the target index and credentials.

## External AI privacy policy

Before any prompt is sent to Groq, the provider boundary filters both the
system and user messages. Global public IP addresses retain the existing policy
and are replaced with `[REDACTED_PUBLIC_IP]`. Private IPv4 and IPv6, loopback,
and link-local addresses are replaced with an opaque `[NONPUBLIC_IP_...]`
pseudonym. Repeated occurrences within one analysis use the same pseudonym,
including across report evidence and analyst notes. A fresh in-memory HMAC salt
is used for each provider request, so pseudonyms are not intended to correlate
addresses between separate analyses.

Standard IP text, bracketed IPv6, IPv6 zone identifiers, IPv4-mapped IPv6, and
recognized malformed IPv6 candidates are handled. Structured fields named
`srcip`, `dstip`, or their common source/destination variants also accept
32-bit integer and `0x` hexadecimal IPv4 forms. In free text, decimal and
hexadecimal integer forms are interpreted only when labeled as an IP or used
as a numeric URL host; bare numbers are left unchanged to avoid rewriting rule
IDs, ports, and ordinary values. Percent-encoded address literals are decoded
up to five times when the result is a recognizable address. Recognized malformed
IP-like candidates are replaced with `[REDACTED_INVALID_IP]`; clock values such
as `12:34:56` are preserved.

These rules cannot reliably identify every encoding, obfuscation, or malformed
address. Bare integer or hexadecimal values without IP context, encodings nested
more than five times, and custom encodings may pass through. The provider
boundary also masks common URLs, fully qualified hostnames, MAC addresses,
explicitly labeled usernames or accounts, and absolute Unix or Windows path
tokens. Pattern filtering cannot guarantee that arbitrary command output or
every identifier is removed. The report API allowlists alert fields, but
descriptions and analyst notes can still contain identifying context.

The Generate Report API sends only allowlisted alert fields and sanitized notes.
Both API endpoints pass their provider-bound prompts through the
provider-boundary filter. Other prompt text, approved alert fields, timestamps,
rule details, and other context may still be sent externally to Groq. Filtering
reduces IP disclosure but does not provide complete anonymization. Pseudonyms
preserve within-analysis correlation, and surrounding context may still
identify a host or person. Review sanitized output and avoid unnecessary
sensitive details.

## Deterministic correlation API

`POST /api/correlations` requires the internal bearer token and accepts an
`alerts` array. It groups alert pairs that share a host, user, or source IP
within `SOC_AI_CORRELATION_WINDOW_MINUTES` (default 15; valid range 1-1440),
then returns group timelines with timestamps, evidence alert IDs, rule IDs,
and shared entities. Connected pairwise links form one group for a sequence
such as SSH failures, success, and sudo. The provider receives only the
grouped timeline and summarizes it; entity values are redacted before the
provider call. If no groups are found, the endpoint returns a deterministic
message without calling a provider.

## Incident API

Every `/api/incidents` route requires the same internal bearer token. Create
an incident with `POST /api/incidents` using either an `alerts` array or a
`correlation_group` with a timeline. `GET /api/incidents` lists incidents;
`GET /api/incidents/<id>` returns evidence, analyst notes, decision log, and
timeline. The `/status`, `/assignment`, `/notes`, and `/decisions` POST routes
record validated workflow changes. `GET /api/incidents/<id>/report` returns a
Markdown report. Allowed statuses are New, Investigating, Escalated, Contained,
Resolved, and Closed; transitions are validated and Closed is terminal.

## Threat-intel API

`POST /api/threat-intel/lookup` accepts an alert object or incident ID and
requires the internal bearer token. It extracts public IPs, public domains,
URLs, and hashes. Private/non-global IPs, internal hostnames, URL credentials,
queries, and fragments are excluded. VirusTotal and AbuseIPDB adapters read
`VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` from the process environment;
these keys must not be sent by a request or stored in source. Results are
cached in SQLite, and each provider has a configurable per-minute request
limit. Only returned provider data is included in the AI summary prompt; when
there is no returned data, the API says so without calling the AI provider.
HTTP behavior is covered with mocks; no live provider request has been run.

## Read-only hunting

`POST /api/hunts/proposals` validates AI-proposed JSON against the local
ATT&CK catalog, the `wazuh-alerts-4.x-*` index allowlist, an allowlist of
query fields and clauses, and a maximum size of 1,000. Scripts and write
operations are rejected. The Dashboard plugin's `POST /api/hunts/run`
controller retrieves the signed-in Wazuh user, asks the backend for a
proposal, validates the query envelope again, and runs it through
`asCurrentUser.search`; the user's OpenSearch permissions therefore apply.
It submits minimized results to `/api/hunts/<id>/results` for interpretation
and storage. Hunt reports are scoped to their creating username. Provider
prompts are privacy-filtered by the existing backend provider boundary.

## Roles and audit

Every `/api/` and `/training/` route is gated by both the internal bearer token
and the role associated with `X-SOC-User` (missing identity falls back to the
least-privileged `local-analyst`). L1 can use analysis/report/training routes;
L2 adds correlation, incidents, and threat intel; L3 adds hunting; admin can
manage users and view audit records. Set comma-separated bootstrap accounts
with `SOC_AI_ADMIN_USERS` in the protected backend environment. Admins can
assign L1, L2, L3, or admin through `PUT /api/admin/users/<username>/role`.

`GET /api/admin/audit` is admin-only. Audit events record the user, action,
object, time, and compact details for analyst decisions, incident status
changes, imports, training progress exports, and role changes. SQLite triggers
reject updates and deletes to the audit table. Route-role and audit behavior
is covered with temporary-database tests.

`POST /api/admin/retention/purge` is admin-only and defaults to `{}` (dry run).
`{"dry_run": false}` performs deletion. Alert rows, raw/imported alert data,
AI/hunting reports, and training attempt reports use configurable
`SOC_AI_ALERT_RETENTION_DAYS` (90 by default) and
`SOC_AI_REPORT_RETENTION_DAYS` (180 by default). The service enforces
`SOC_AI_MAX_REQUEST_BYTES` (1 MiB default, maximum 10 MiB) and
`SOC_AI_RATE_LIMIT_PER_MINUTE` (120 per route and client by default).

The optional synthetic local load check is `python scripts/load-test.py` from
the repository root. Set `SOC_AI_INTERNAL_TOKEN`; it only requests the
authenticated training scenario list. The load script is documented and has
not been run.

## Evidence assistant

`POST /api/assistant/chat` accepts a question and up to ten `{type, id}`
references for alert, report, incident, or hunt records. It loads only stored
objects available to the authenticated user's role (L1 reports/alerts, L2
incidents, L3 hunts; hunts are owner-scoped) and sends that evidence through
the standard privacy-filtered provider boundary. Answers must cite source
IDs as `[type:id]`. If no referenced object is accessible, it returns a
deterministic refusal without a provider call. Coverage uses mocked providers
and temporary databases.

## Security notes

- Never commit API keys, passwords, private keys, databases, or real security logs.
- The privacy filter covers selected patterns; it does not guarantee complete anonymization.
- Review alerts and sanitized output before sending data to an external AI provider.
- AI-generated explanations can be incorrect. A human analyst must verify them before taking action.
- Use synthetic alerts for demonstrations until privacy controls have been validated against your own data.

## Project status

The repository includes synthetic integrations, OpenSearch role examples, an importer, training workflows, and backend tests. The current suite count is reported in the root README. Automated processing of selected real alerts is not yet considered production-ready.

## Author

Albin Thomas — Cybersecurity and SOC Analyst Learning
