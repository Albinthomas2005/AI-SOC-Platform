# Threat model

This is a source-based overview of trust boundaries and controls present in the repository. It is not a deployment security assessment.

## Assets and boundaries

- Wazuh alert contents, analyst notes, reports, identities, internal bearer token, SQLite records, and provider credentials.
- Dashboard browser/server, Flask backend, local database, and external Groq provider are separate trust boundaries. Ollama is constrained by code to loopback URLs.

## Threats and current controls

| Threat | Controls present in code | Remaining concern |
|---|---|---|
| Prompt injection in log content | Alert-field allowlisting and privacy sanitization; the human review workflow keeps reports as drafts | No dedicated prompt-injection detector or isolation guarantee; malicious instructions in alert text may influence model output |
| Hallucinated IOCs or ATT&CK mappings | A local ATT&CK catalog is used to validate hunt proposals; report decisions require analyst action | Validated identifiers do not prove an IOC or mapping is factually correct; analyst verification is still required |
| Leakage to external AI | Minimized alert fields and provider-boundary filtering before generation; Ollama can be configured for loopback | Pattern-based filtering is incomplete; Groq prompts leave the local environment; local mode has not been tested against a live model |
| Internal token misuse | Bearer token authentication, request size/rate limits, and loopback bind defaults | No token rotation facility or proof of secret-manager integration; deployment must protect the token |
| Role bypass or confused identity | Backend role gate reads `X-SOC-User`; Dashboard integration maps the signed-in user via `SOC_AI_USERNAME_MAP`; backend applies L1/L2/L3/admin thresholds | Incorrect Dashboard mapping or deployment configuration can assign the wrong identity; live authorization integration is unverified |

## Additional limitations

The filter does not guarantee anonymization and custom or obfuscated identifiers can remain. It redacts sensitive structured field names such as `private_key` but does not identify arbitrary PEM private-key blocks in free text. The role system depends on correct user mapping and explicit provisioning. SQLite file permissions and deployment backups must be managed by the operator. No production readiness claim is made.

## Review questions for deployment

- Is the backend reachable only by the trusted Dashboard server?
- Are bearer tokens and provider keys stored outside source control and logs?
- Is the Dashboard username map reviewed and kept current?
- Are database access, retention, backups, and deletion practices appropriate for the environment?
- Are analysts instructed to validate provider output against alert evidence?
