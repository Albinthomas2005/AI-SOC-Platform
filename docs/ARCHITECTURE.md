# Architecture

## Components

- **Wazuh Dashboard plugin:** TypeScript server controllers use the authenticated Dashboard context to retrieve alert evidence and proxy operations to Flask. The plugin UI provides the analysis and phase workbench.
- **Flask backend:** `backend/app.py` registers token-protected analysis, report, correlation, incident, threat-intel, and training routes. `roles_audit.py` checks the mapped SOC identity and minimum role.
- **Privacy boundary:** `privacy_filter.py` minimizes selected alert fields and sanitizes provider-bound prompts. One in-memory context pseudonymizes addresses consistently within a provider request.
- **AI providers:** Groq is the default. Ollama is supported only at localhost/loopback URLs. Provider adapters are in `backend/ai_providers.py` and `backend/groq_service.py`.
- **Persistence:** SQLite stores reports, decisions, SOC roles, audit events, and training data. The database path can be configured; the default local file is ignored by Git.
- **Training content:** `datasets/training/` contains scenarios and draft answer keys. `data/mitre_techniques.json` is the local ATT&CK catalog (706 entries).

## Analysis and report flow

1. The Dashboard controller fetches the selected Wazuh document as the signed-in Dashboard user.
2. The controller sends minimized evidence to the local Flask backend with its internal bearer token.
3. Flask authenticates the token and enforces the role for the route.
4. The backend re-applies field allowlisting and privacy filtering before provider generation.
5. The generated report is presented as an AI draft.
6. An analyst can edit, approve, or reject it. The backend stores the decision and sanitized evidence in SQLite.

The plugin defaults to `http://127.0.0.1:5000` when an explicit backend URL is not configured. A live Dashboard end-to-end run has not been verified.

## Trust boundaries

| Boundary | Data/control crossing it |
|---|---|
| Browser to Dashboard plugin | User interactions and selected record reference |
| Dashboard server to Wazuh/OpenSearch | Alert lookup using the signed-in user context |
| Dashboard server to Flask | Minimized evidence, bearer token, mapped SOC username |
| Flask to AI provider | Filtered prompt and allowed evidence; Groq is external, Ollama is local-loopback only |
| Flask to local SQLite | Drafts, decisions, role mappings, audit events, and training records |

## Verification status

Automated backend tests exercise API and privacy logic. They do not establish live provider behavior, live Dashboard compatibility, deployment security, or production readiness. The `/api/hunts/run` controller is in the Dashboard plugin; the Flask application does not register that POST path.
