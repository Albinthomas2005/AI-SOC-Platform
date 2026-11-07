# Architecture

## Components

- **Wazuh Dashboard 4.14.9 plugin:** existing Threat Hunting AI Analysis UI plus the AI SOC Dashboard overview and report drafting UI.
- **Dashboard server routes:** authenticate the request, validate the alert index and document reference, retrieve minimized alert fields using the signed-in user's OpenSearch client, and call the backend through loopback.
- **Python backend:** Flask endpoints for alert analysis and Generate Report, input bounds, evidence allowlisting, privacy filtering, and provider integration.
- **AI provider:** called only by the backend. Provider output is advisory and is labeled unverified.

## Trust boundaries

Browser supplied alert data is not trusted as evidence: routes accept a record reference and fetch the record under the current user's permissions. `SOC_AI_INTERNAL_TOKEN` is server side. Do not expose it to frontend code, source control, logs, or error messages. Privacy filtering redacts public IPs, pseudonymizes nonpublic addresses within an analysis, and removes configured sensitive values before external analysis.

## Main flows

- Threat Hunting AI Analysis uses `POST /api/ai/analyze-alert` in the Dashboard and backend.
- Generate Report uses `POST /api/ai/generate-report`; drafts include bounded analyst notes and evidence references and are not persisted automatically.
- The AI SOC Dashboard queries Wazuh alert data and links analysts into the existing Threat Hunting workflow.

There is no autonomous remediation flow in this project.
