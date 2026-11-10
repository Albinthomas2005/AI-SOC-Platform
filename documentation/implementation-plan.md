# Implementation and integration record

## Included implementation

- Backend snapshot: `6f8a35a04a20e9ec6917c192f99e1808e4c7b216` (`fix: strengthen AI SOC IP privacy sanitization`). This commit descends from the backend `main` snapshot `da1e098` and retains the authenticated Generate Report API while adding stronger privacy filtering and expanded tests.
- Dashboard base: Wazuh `4.14.9`, OpenSearch Dashboards `2.19.6`, based on commit `e457fdd91` (`Run lint and Jest after Wazuh 4.x build`). The working tree changes present at integration time are included, including the Generate Report controller and route, and report route tests.
- Existing Threat Hunting AI Analysis UI and `/api/ai/analyze-alert` controller path are retained alongside the new report workflow.

## Integration principles

1. Keep the signed-in user's OpenSearch permissions on alert retrieval.
2. Keep provider tokens on the server and sanitize/minimize before provider calls.
3. Label AI reports as unverified and require analyst review.
4. Preserve the original source repositories and worktrees as backups.
5. Keep synthetic datasets explicitly labeled and exclude local data and credentials.

## Follow-up validation

Run the Python unit suite and the Wazuh 4.14.9 plugin lint, Jest, and build commands in their matching development environment. Review deployment-specific backend binding and environment configuration before connecting real alert data.
