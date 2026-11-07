# AI SOC Platform

[![Backend tests](https://github.com/Albinthomas2005/AI-SOC-Platform/actions/workflows/backend-tests.yml/badge.svg?branch=main)](https://github.com/Albinthomas2005/AI-SOC-Platform/actions/workflows/backend-tests.yml)

An educational security operations platform that combines a Python AI analysis service with a Wazuh 4.14.9 Dashboard plugin. The dashboard retrieves alert evidence as the signed-in Wazuh user and makes server-side requests to the local backend. The backend filters sensitive data before sending content to the configured AI provider.

## Repository layout

- [`backend/`](backend/): Flask service, privacy filtering, Generate Report and AI analysis APIs, tests, and setup notes.
- [`wazuh-dashboard/`](wazuh-dashboard/): Wazuh Dashboard 4.14.9 plugin source with the existing Threat Hunting AI Analysis integration, AI SOC Dashboard, and Generate Report workflow.
- [`datasets/simulated-alerts/`](datasets/simulated-alerts/): clearly labeled synthetic alert examples only.
- [`documentation/`](documentation/): architecture, setup, and implementation notes.

## Request flow

1. A signed-in analyst opens a Wazuh alert or the AI SOC Dashboard.
2. Dashboard server code retrieves alert fields through the current user's OpenSearch permissions.
3. The server sends a bounded request to the backend over loopback using `SOC_AI_INTERNAL_TOKEN`.
4. The backend minimizes and sanitizes the evidence and analyst notes before an AI provider call.
5. The response is presented as AI-generated, unverified analysis for analyst review.

The dashboard does not send provider credentials to the browser. Report drafts are not automatically saved or used to trigger response actions.

## Quick start

See [backend setup](backend/README.md) and [installation notes](documentation/installation.md). Configure the same strong internal token in the backend's protected environment and the Wazuh Dashboard server environment; never commit it.

## Project status

| Area | Status |
|---|---|
| AI Alert Analysis in the dashboard | Verified in the dashboard |
| Backend unit tests | Passing locally (66 tests) |
| Backend CI | Root GitHub Actions workflow is configured; remote run status has not been checked here |
| Generate Report in the dashboard | Pending end-to-end verification |
| Dashboard plugin rebuild with the 45-second timeout | Pending |
| AI SOC Dashboard page | Pending end-to-end verification |
| Synthetic evaluation results | Pending; see [evaluation report](documentation/evaluation.md) |

## Validation

Backend unit tests:

```bash
cd backend
python -m unittest discover -s tests -v
```

GitHub Actions runs the backend suite from [`.github/workflows/backend-tests.yml`](.github/workflows/backend-tests.yml).

Dashboard build and tests require a matching Wazuh 4.14.9 / OpenSearch Dashboards 2.19.6 development environment. See [installation](documentation/installation.md) for the expected commands and environment constraint.

## Dataset notice

Files under `datasets/simulated-alerts/` are synthetic examples for development and tests. They are not production telemetry and must not be represented as real incidents.

## License and attribution

`wazuh-dashboard/` is a fork of Wazuh Dashboard, Copyright Wazuh, Inc., distributed under GPL-2.0. The root [`LICENSE`](LICENSE) is copied from that project. The `backend/` code is also released under GPL-2.0 unless the repository owner chooses a different license.

<!-- TODO: Repository owner: confirm whether GPL-2.0 should also apply to backend/. -->
