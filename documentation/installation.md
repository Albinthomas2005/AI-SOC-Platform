# Installation and development

## Backend

Use Python 3.10 or newer. From `backend/`, create and activate a virtual environment, install `requirements.txt`, and copy `.env.example` to a local `.env`. Set provider credentials and a strong `SOC_AI_INTERNAL_TOKEN` in that ignored file. The Flask service exposes only the token-protected `/api/ai/analyze-alert` and `/api/ai/generate-report` endpoints.

Run backend tests from `backend/`:

```bash
python -m unittest discover -s tests -v
```

## Wazuh Dashboard plugin

The dashboard source is pinned to Wazuh `4.14.9` and OpenSearch Dashboards `2.19.6` (see `wazuh-dashboard/VERSION.json` and plugin manifests). Build and test it in the matching full Wazuh Dashboard development environment, following `wazuh-dashboard/docs/dev/setup.md` and `wazuh-dashboard/docs/dev/run-tests.md`.

Configure `SOC_AI_INTERNAL_TOKEN` and the same `SOC_AI_PORT` in the Dashboard
server and backend process environments. The port defaults to `5000`; the
plugin controller and backend runner both read `SOC_AI_PORT`. Keep the host on
loopback unless deployment networking has been separately reviewed.

## Data

The only included alert example is under `datasets/simulated-alerts/` and is synthetic. Use authorized, sanitized data for any local integration work; do not add real customer or production alert exports to this repository.
