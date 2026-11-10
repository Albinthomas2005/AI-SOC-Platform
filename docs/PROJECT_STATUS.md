# AI-SOC-Platform project audit

Audit date: 2026-11-07 (historical snapshot; Phase 1 changes are summarized below)
Branch inspected: `feature/portfolio-polish` (`92d910e`, `Add optional local Ollama provider`)
Scope: read-only source, test, Git metadata, and saved-evaluation review. No network, GitHub CLI, or Groq calls were made. No application tests or dashboard build were run as part of this audit. Findings below distinguish source-code inspection from runtime verification.

## Executive summary

The repository contains a Flask service, a Wazuh Dashboard 4.14.9 plugin fork, an optional Ollama provider, a Groq provider, a synthetic evaluation harness, and backend/plugin tests. The intended path is Wazuh alert lookup through the Dashboard server, then a token-authenticated loopback backend request and an AI provider call. The selected-alert AI Analysis tab has since been connected to report generation and edit/approve/reject decisions. Its browser test is written but not run for Phase 1.

Security controls include backend bearer-token authentication, Dashboard current-user checks, an alert-field allowlist, pattern-based privacy filtering, and loopback binding by default. These reduce exposure but do not establish complete anonymization or production hardening. The historical audit observed a local SQLite database with mode `0644`; its current presence and mode were not checked for Phase 1. A complete secret scan, live service check, live provider check, and plugin build were not performed for Phase 1.

The latest saved evaluation report records 8/14 scenarios passing, with six failures. The stored report contains check outcomes but no model response bodies, so several failure causes cannot be identified from evidence. See [Evaluation results and six failures](#evaluation-results-and-six-failures).

## 1. Architecture and data flow

1. **Alert selection and lookup:** In Threat Hunting, the plugin adds an AI Analysis tab for the `threat-hunting` module ([`wazuh-dashboard/plugins/main/public/components/common/wazuh-discover/wz-discover.tsx:222–238`](../wazuh-dashboard/plugins/main/public/components/common/wazuh-discover/wz-discover.tsx)). The Dashboard server controller looks up the selected alert through OpenSearch as the current Dashboard user and requests only its mirrored allowlist of fields ([`wazuh-dashboard/plugins/main/server/controllers/wazuh-ai.ts:59–79,247–270`](../wazuh-dashboard/plugins/main/server/controllers/wazuh-ai.ts)).
2. **Dashboard-to-backend request:** The route checks that a current user exists and validates the index/alert reference before forwarding the minimized alert to the configured loopback port (`SOC_AI_PORT`, default `5000`) with the internal bearer token ([`wazuh-dashboard/plugins/main/server/controllers/wazuh-ai.ts`](../wazuh-dashboard/plugins/main/server/controllers/wazuh-ai.ts)). The API routes are registered at [`wazuh-dashboard/plugins/main/server/routes/wazuh-ai.ts`](../wazuh-dashboard/plugins/main/server/routes/wazuh-ai.ts).
3. **Backend validation and persistence:** Flask checks bearer authentication, parses JSON, applies backend-side evidence minimization and sanitization, calls the AI service, and stores a record ([`backend/app.py:59–137`](../backend/app.py)). The report endpoint performs additional size, index, note, ID, and field checks ([`backend/app.py:140–237`](../backend/app.py)).
4. **Provider call:** The service chooses Groq by default or Ollama when `SOC_AI_PROVIDER` selects it ([`backend/groq_service.py:65–71`](../backend/groq_service.py); [`backend/ai_providers.py:18–50`](../backend/ai_providers.py)). The Groq path reads its key from the environment and sends the constructed prompt to the configured model ([`backend/groq_service.py:99–136`](../backend/groq_service.py)). The prompt includes alert evidence and treats it as untrusted input ([`backend/groq_service.py:139–175`](../backend/groq_service.py)).
5. **Results and decisions:** The selected-alert AI Analysis tab requests a report, displays its unreviewed status, and exposes edit/approve/reject controls. Decisions go through the Dashboard server and backend endpoint and are stored in SQLite ([`wazuh-dashboard/plugins/main/public/components/common/wazuh-discover/components/ai-analysis-tab.tsx`](../wazuh-dashboard/plugins/main/public/components/common/wazuh-discover/components/ai-analysis-tab.tsx); [`wazuh-dashboard/plugins/main/server/controllers/wazuh-ai.ts`](../wazuh-dashboard/plugins/main/server/controllers/wazuh-ai.ts); [`backend/app.py`](../backend/app.py)). The browser test is written but has not been run.

The backend also includes a Wazuh importer, but the inspected application flow does not require it for Dashboard-initiated analysis. The importer writes selected event data into SQLite ([`backend/wazuh_importer.py:57–84`](../backend/wazuh_importer.py)).

## 2. Security review

### Authentication, network exposure, and access control

- **Backend authentication — implemented in source, runtime not verified.** The two AI operations and decision endpoint use a bearer token checked with constant-time comparison ([`backend/app.py:59–72,75–78,140–143,239–243`](../backend/app.py)). Missing or invalid tokens are rejected in code. No live 401/authorized request was made.
- **Dashboard authentication — implemented in source, runtime not verified.** Controllers require a current Dashboard user and use the current user's OpenSearch client for alert retrieval ([`wazuh-dashboard/plugins/main/server/controllers/wazuh-ai.ts:188–204,247–270`](../wazuh-dashboard/plugins/main/server/controllers/wazuh-ai.ts)).
- **IP allowlist — not present.** No backend source-level client-IP allowlist was found. The app defaults to loopback and rejects non-loopback bind hosts unless explicitly overridden ([`backend/app.py:295–313`](../backend/app.py)). Binding to loopback is a network exposure control, not a client IP allowlist. If `SOC_AI_ALLOW_NON_LOOPBACK=true` is used, deployment firewalling and authentication become especially important.
- **CORS — no explicit backend CORS configuration found.** The plugin uses same-origin Dashboard server routes that proxy to the backend; this is consistent with avoiding browser-to-backend cross-origin calls. Browser/CSP behavior was not runtime-tested.

### Privacy and data handling

- **Allowlisting:** Backend evidence minimization selects known Wazuh fields and bounds values ([`backend/privacy_filter.py:90–110,333–369`](../backend/privacy_filter.py)). This excludes fields such as `full_log`, arbitrary usernames, commands, and unlisted `data.*` values from those paths. The Dashboard maintains a second allowlist ([`wazuh-dashboard/plugins/main/server/controllers/wazuh-ai.ts:59–79`](../wazuh-dashboard/plugins/main/server/controllers/wazuh-ai.ts)). Keeping the two lists synchronized is a maintenance risk.
- **Pattern filtering:** The filter handles common email, IP, bearer-token, and secret-label patterns ([`backend/privacy_filter.py:9–88,267–298`](../backend/privacy_filter.py)). It is not a general anonymizer. The optional strict mode also attempts to mask URLs, hostnames, MAC addresses, usernames, and paths, but remains pattern-based ([`backend/privacy_filter.py:258–264,296–298`](../backend/privacy_filter.py); default configuration is in [`backend/groq_service.py:79–80`](../backend/groq_service.py)).
- **IP edge cases:** `_mask_address` handles private/loopback/link-local and public addresses, but the fallback returns other non-global address strings unchanged ([`backend/privacy_filter.py:132–150`](../backend/privacy_filter.py)). Review and test reserved, multicast, and other special-use ranges before treating IP handling as comprehensive.
- **Provider payload:** Allowlisted descriptions, rule metadata, timestamps, and other selected context can still be sent to Groq when Groq is selected; the filter reduces disclosure but cannot promise anonymity ([`backend/groq_service.py:139–175,207–265`](../backend/groq_service.py); [`backend/README.md:185–200`](../backend/README.md)). With Ollama, the provider adapter only permits loopback endpoints in source ([`backend/ai_providers.py:18–50`](../backend/ai_providers.py)); actual deployment locality and model behavior were not verified.
- **SQLite:** `backend/soc_alerts.db` was present locally with file mode `0644`. The schema and persistence helpers are in [`backend/database.py:6–17,123–128`](../backend/database.py). The importer stores a source IP and alert metadata ([`backend/wazuh_importer.py:57–84`](../backend/wazuh_importer.py)); the API stores minimized alert evidence and AI output ([`backend/app.py:106–113,204–215`](../backend/app.py)). No encryption-at-rest, retention policy, or explicit restrictive file mode was found in these paths. Local user access and backup exposure therefore merit review. No database contents were printed.
- **Analyst decisions:** Decision notes and edited report text are accepted and stored ([`backend/app.py:239–292`](../backend/app.py); persistence in [`backend/database.py`](../backend/database.py)). Although length and type are validated, edited text is analyst-supplied content and may itself contain sensitive material. Access, retention, and audit actor identity should be considered.

### Secrets, validation, errors, and prompt injection

- **Secrets in tracked files/history — no match in a limited signature scan; not fully verified.** `.env` is ignored by [`backend/.gitignore:1`](../backend/.gitignore), and tracked-path checks found no obvious `.env` or key-named file. A limited pattern scan across tracked content and Git history found no common private-key, Groq `gsk_`, GitHub-token, AWS-key, or OpenAI `sk-` signatures. Dedicated scanners were unavailable, and signature scans cannot detect every secret format. A local ignored `.env` exists; its values were not read or displayed. Do not interpret this as proof that history contains no secrets.
- **Input bounds:** Flask has a global request size cap ([`backend/app.py:35–38`](../backend/app.py)); report generation additionally bounds body size, note length, alert IDs, and index names ([`backend/app.py:140–190`](../backend/app.py)). Decision text is also bounded ([`backend/app.py:259–278`](../backend/app.py)). JSON nesting depth and computational complexity are not explicitly constrained in the inspected code.
- **SQL:** Persistence helpers use parameterized SQLite operations; no SQL string interpolation issue was identified in the reviewed paths ([`backend/database.py`](../backend/database.py)).
- **Error messages:** Flask generally returns fixed/generic client errors and catches provider failures rather than returning raw exception text ([`backend/app.py:114–128,219–237`](../backend/app.py); [`backend/groq_service.py:99–136`](../backend/groq_service.py)). Dashboard controllers also map upstream failures to generic responses. No obvious stack trace or secret echo path was identified statically; runtime logs and all exception branches were not exhaustively tested.
- **Prompt injection:** The prompt explicitly marks alert JSON as untrusted and says not to follow instructions within it ([`backend/groq_service.py:161–175`](../backend/groq_service.py)). The alert description still reaches the language model as prompt content. This is a mitigation, not a security boundary; a model could follow or repeat malicious text. The saved prompt-injection scenario fails both its keyword and forbidden-claim checks (see below), but its response was not retained, so the exact behavior is **not verified**.

## 3. AI quality and evaluation

### Schema and safety enforcement

- `validate_analysis_response` checks for an “Alert fields relied on” line, one known alert field reference, a low/medium/high confidence value, and a nonempty “what is not known” line ([`backend/groq_service.py:34–62`](../backend/groq_service.py)). These checks enforce a minimal shape; they do not prove that the cited fields support the statements or that confidence is calibrated.
- The analysis prompt requests facts versus hypotheses, evidence grounding, cautious language, and a MITRE ATT&CK hypothesis only when supported ([`backend/groq_service.py:139–175`](../backend/groq_service.py)). Prompt instructions alone do not guarantee compliance.
- MITRE reference validation consults a local technique catalog ([`backend/mitre_validation.py:8–9,47–91`](../backend/mitre_validation.py)). The expected `data/mitre_techniques.json` catalog was absent; only [`data/README.md`](../data/README.md) was present. In that state, IDs can be retained but marked unverified rather than checked against an authoritative local list. Catalog-backed validation is therefore **not verified** on this checkout.
- Report validation checks for required report headings and labels the report AI-generated/unverified ([`backend/groq_service.py:207–265`](../backend/groq_service.py); API response in [`backend/app.py:204–237`](../backend/app.py)). It does not establish factual correctness.

### Evaluation results and six failures

The latest saved run is recorded in [`documentation/evaluation.md:3,7–22`](../documentation/evaluation.md): 14 synthetic cases, 8/14 overall passes, timestamp 2026-11-07 07:06 UTC. The response bodies were not saved. The evaluator uses literal substring and phrase checks ([`backend/scripts/run_eval.py:54–81`](../backend/scripts/run_eval.py)); it can reject a semantically safe synonym or a forbidden phrase that appears in a quote or negation. The entries below separate observed failed checks from guesses about causes.

| Failed scenario | Observed failure | Most likely source / evidence | Cause assessment |
|---|---|---|---|
| SYNTHETIC: Privilege escalation | Required keyword check failed; MITRE input already contains `T1068` ([`documentation/evaluation.md:11`](../documentation/evaluation.md); [`datasets/simulated-alerts/scenarios.json`](../datasets/simulated-alerts/scenarios.json)) | The evaluator checks required terms literally ([`backend/scripts/run_eval.py:54–63`](../backend/scripts/run_eval.py)); prompt asks for evidence-grounded analysis ([`backend/groq_service.py:139–175`](../backend/groq_service.py)). | The saved record does not identify the missing term. Any explanation (e.g. wording mismatch) is a **guess**. |
| SYNTHETIC: Suspicious connection | Keyword check failed; input includes `T1571` and synonym alternatives ([`documentation/evaluation.md:16`](../documentation/evaluation.md); scenario near [`datasets/simulated-alerts/scenarios.json:293–303`](../datasets/simulated-alerts/scenarios.json)) | Literal/synonym checking is in [`backend/scripts/run_eval.py:54–63`](../backend/scripts/run_eval.py). | The response is unavailable; cannot distinguish omission from valid paraphrase. A synonym mismatch is a **guess**. |
| SYNTHETIC: Benign successful login | Forbidden-phrase check failed ([`documentation/evaluation.md:19`](../documentation/evaluation.md); scenario near [`datasets/simulated-alerts/scenarios.json:396–424`](../datasets/simulated-alerts/scenarios.json)) | The scenario's `must_not_claim` list is mechanically checked by [`backend/scripts/run_eval.py:75–81`](../backend/scripts/run_eval.py); prompt requests cautious conclusions ([`backend/groq_service.py:161–168`](../backend/groq_service.py)). | The phrase and context are not recorded. Model overclaim or a quoted/negated phrase false positive are both **guesses**. |
| SYNTHETIC: Routine package update | Forbidden-phrase check failed ([`documentation/evaluation.md:20`](../documentation/evaluation.md); scenario near [`datasets/simulated-alerts/scenarios.json:427–454`](../datasets/simulated-alerts/scenarios.json)) | Same literal forbidden-phrase checker and cautious prompt cited above. | Exact phrase/context is absent; overclaim or a checker false positive is a **guess**. |
| SYNTHETIC: Prompt injection in alert description | Keyword and forbidden-phrase checks failed ([`documentation/evaluation.md:21`](../documentation/evaluation.md); scenario [`datasets/simulated-alerts/scenarios.json:457–483`](../datasets/simulated-alerts/scenarios.json)) | The untrusted-data rule is in [`backend/groq_service.py:170–175`](../backend/groq_service.py), while attacker text remains in the alert description and is sent in the prompt. The evaluator is literal ([`backend/scripts/run_eval.py:54–81`](../backend/scripts/run_eval.py)). | Whether the model obeyed the injection, omitted terms, or safely quoted a forbidden phrase is **not verified**; attributing it to injection success is only a **guess**. |
| SYNTHETIC: Encoded PowerShell without input MITRE mapping | Independent MITRE check failed; expected `T1059.001` was absent ([`documentation/evaluation.md:22`](../documentation/evaluation.md); scenario [`datasets/simulated-alerts/scenarios.json:486–514`](../datasets/simulated-alerts/scenarios.json)) | Prompt asks for MITRE only when supported ([`backend/groq_service.py:161–175`]); validator cannot establish catalog validity without the absent catalog ([`backend/mitre_validation.py:47–81`](../backend/mitre_validation.py)). | The saved evidence establishes only that the ID string was absent. Model omission/cautious interpretation is a **guess**; no response body is available. |

The separate [`docs/EVALUATION.md:3–7`](EVALUATION.md) accurately points to the saved run and explains that responses are unavailable. However, [`documentation/evaluation-analysis.md:1`](../documentation/evaluation-analysis.md) still describes a 4/10 baseline and is stale relative to the saved 14-case 8/14 report. Reconcile it before using it as current evidence.

## 4. Tests and coverage gaps

- Backend test modules cover API behavior, provider adapters, app configuration, MITRE validation, privacy filtering, evaluation checks, importer, and Wazuh integration. A source count found 88 `test_` methods across those files; this is a static count, not a test execution result.
- Tests mock providers and exercise local behavior; they do not validate current Groq/Ollama model quality, provider availability, or external API behavior.
- **Critical isolation risk:** `backend/app.py` calls `init_db()` during module import ([`backend/app.py:55–56`](../backend/app.py)). `backend/tests/test_ai_api.py` imports the app at module scope before test setup patches database paths. Running the suite may therefore open/create the configured local database before tests isolate it. This audit did not run the suite to avoid an unintended database write. Prefer an app factory or defer database initialization, and patch paths before importing the app.
- MITRE catalog-present behavior cannot be validated against the intended full catalog because the JSON file is absent. Existing unit tests can test mocked/small catalogs but do not prove full Enterprise coverage.
- Plugin test files cover portions of route/controller and UI behavior, but the Dashboard build, lint, and Jest suite were not run. The root plugin workflow is `workflow_dispatch` only ([`.github/workflows/build-dashboard-plugin.yml:1–8`](../.github/workflows/build-dashboard-plugin.yml)); lint/Jest are optional and default off ([`.github/workflows/build-dashboard-plugin.yml:9–16`](../.github/workflows/build-dashboard-plugin.yml)).
- AI Analysis route tests cannot establish real Wazuh/OpenSearch integration behavior, network timeout behavior, or the installed Dashboard plugin runtime. The timeout is 45 seconds in source ([`wazuh-dashboard/plugins/main/server/controllers/wazuh-ai.ts:53–58`](../wazuh-dashboard/plugins/main/server/controllers/wazuh-ai.ts)).
- Exact coverage percentages and untested branch coverage were **not verified**; no coverage report was generated.

## 5. Dashboard plugin flows and runtime risks

### Threat Hunting AI Analysis

The shared tab is registered for Threat Hunting, Malware Detection Events, MITRE Events, and the MITRE technique recent-events flyout ([`wz-discover.tsx`](../wazuh-dashboard/plugins/main/public/components/common/wazuh-discover/wz-discover.tsx); [`ai-analysis-tabs.tsx`](../wazuh-dashboard/plugins/main/public/components/common/wazuh-discover/components/ai-analysis-tabs.tsx); [`flyout-technique.tsx`](../wazuh-dashboard/plugins/main/public/components/overview/mitre/framework/components/techniques/components/flyout-technique/flyout-technique.tsx)). It uses the same same-origin authenticated report route with only the selected alert index and ID; returned report text is displayed without Markdown interpretation. Plugin render tests are written, not run.

The historical audit found that the analyze controller dropped the ID and had no decision controls. Phase 1 changes the selected-alert tab to request a stored report and send edit/approve/reject decisions through the protected Dashboard and backend routes. The browser test is written, not run.

Potential runtime failure points, **not verified on an installed Dashboard**:

- Backend must be reachable at loopback `SOC_AI_PORT` (default `5000`) and the Dashboard service must receive the matching internal token.
- The selected user's OpenSearch permissions and index pattern must allow alert searches; 403/404 handling exists, but actual role mappings were not exercised ([`wazuh-ai.ts:247–296`](../wazuh-dashboard/plugins/main/server/controllers/wazuh-ai.ts)).
- Dashboard and backend allowlists must remain aligned; a field omitted at either layer will not reach analysis.
- The new selected-alert report/review flow is covered by a browser test that is written, not run.
- Plugin compatibility is pinned in source to Wazuh Dashboard 4.14.9 and OSD 2.19.6 ([`wazuh-dashboard/VERSION.json:2`](../wazuh-dashboard/VERSION.json); [`wazuh-dashboard/plugins/main/package.json:3–6`](../wazuh-dashboard/plugins/main/package.json)). The build workflow's manual trigger and optional checks limit automatic validation.

The existing generic visualization export button is a separate ReportingService flow, not an AI report export ([`wazuh-dashboard/plugins/main/public/components/modules/buttons/generate_report.tsx:25–79`](../wazuh-dashboard/plugins/main/public/components/modules/buttons/generate_report.tsx)).

## 6. Documentation claims versus code

| Document claim | Code evidence | Audit result |
|---|---|---|
| Architecture documentation says report drafts are not saved ([`documentation/architecture.md:17`](../documentation/architecture.md)); backend README repeats that claim ([`backend/README.md:90–93`](../backend/README.md)). | Generate Report persists the result with `save_ai_analysis` ([`backend/app.py:204–215`](../backend/app.py)). | **Does not match code.** Update docs to explain what is stored, its access/retention, and privacy implications. |
| Installation documentation says only analyze-alert and generate-report endpoints exist ([`documentation/installation.md:5`](../documentation/installation.md)). | A third protected decision endpoint exists ([`backend/app.py:239–292`](../backend/app.py)). | **Incomplete.** Document the decision endpoint and clarify its intended callers. |
| Backend README reports 23 privacy tests and 53 total backend tests ([`backend/README.md:204`](../backend/README.md)). | Current tree has 88 `test_` method definitions by static count. | **Stale or inconsistent.** A static method count is not a verified run count; update after executing tests safely. |
| Root README reports 88 tests passed ([`README.md:67`](../README.md)). | No tests were run in this audit; import-time DB initialization is a possible side effect. | Claim is **not independently verified** here. |
| Evaluation analysis says 4/10 baseline ([`documentation/evaluation-analysis.md:1`](../documentation/evaluation-analysis.md)). | Current saved evaluation is 14 scenarios and 8/14 ([`documentation/evaluation.md:3,11–22`](../documentation/evaluation.md)). | **Outdated.** Reconcile or archive the old analysis. |
| Privacy docs describe the configured Groq API as third party ([`docs/PRIVACY.md:46`](../docs/PRIVACY.md)). | Provider selector also supports local Ollama ([`backend/groq_service.py:65–71`](../backend/groq_service.py); [`backend/ai_providers.py:18–50`](../backend/ai_providers.py)). | Qualify the statement by provider selection; default remains Groq. |
| Dashboard analysis and report capabilities are described in project docs. | AI Analysis controller drops analysis ID; report page has decisions. | Documentation should distinguish report decision controls from Threat Hunting AI Analysis decisions. |

## 7. Ranked fixes by impact

Effort: S = small, M = medium, L = large. Ranking considers security and correctness impact, not implementation order.

| Rank | Fix | Impact | Effort |
|---:|---|---|:---:|
| 1 | Set restrictive SQLite permissions/umask, define retention, and minimize or protect stored evidence and analyst text. | Reduces local disclosure of alert/report data; the observed DB mode was `0644`. | M |
| 2 | Remove import-time database initialization and isolate tests from the real project DB before running the suite. | Prevents test imports from touching local data; enables safe repeatable verification. | M |
| 3 | Provide and validate an authoritative Enterprise ATT&CK catalog; fail clearly or mark all IDs unverified when absent. | Makes technique IDs auditable instead of relying on unavailable catalog data. | M |
| 4 | Re-run the 14-case evaluation with local response capture, then update current failure analysis and preserve sensitive outputs locally. | Identifies exact failure causes; current report only records pass/fail. | S |
| 5 | Improve injection resilience and evaluation semantics (context-aware forbidden-claim checks, citations/evidence checks, adversarial tests). | Reduces risk from untrusted alert descriptions and false evaluation failures. | L |
| 6 | Pass `analysis_id` through the Dashboard analyze controller and provide decision controls for Threat Hunting AI Analysis, or explicitly scope decisions to reports. | Closes the persistence/UI gap for analyst review. | M |
| 7 | Add explicit actor identity/audit history and access/retention rules for approve/edit/reject decisions. | Makes decisions attributable and supports review lifecycle. | M |
| 8 | Review privacy behavior for reserved IP ranges and add tests for all documented patterns and known gaps. | Avoids assuming uncommon identifiers are anonymized. | M |
| 9 | Add production deployment hardening: WSGI server, file ownership, service restrictions, secret rotation guidance, and rate limiting. | Improves resilience and limits brute-force/resource abuse beyond loopback deployments. | L |
| 10 | Make plugin lint/Jest checks required in CI and add a version-matched build/install smoke test. | Catches UI/type/runtime regressions before installation; current build is manual and optional checks default off. | M |

## 8. Verification limits

The following are **not verified** by this source audit:

- Backend test pass/fail and coverage. Tests were deliberately not executed because app import calls `init_db()` before test setup may isolate the database.
- Live backend health, token-protected requests, Groq/Ollama connectivity, model output quality, or API-key validity.
- Wazuh Manager, Indexer, Dashboard status, OpenSearch roles, installed plugin behavior, and real alert flow.
- Dashboard TypeScript build, lint, Jest suite, artifact generation, or compatibility on an installed 4.14.9 host.
- Complete secret absence. Only limited known-signature scans were available; secret values were not printed.
- Full ATT&CK technique validation because `data/mitre_techniques.json` is absent.
- Exact causes of the six evaluation failures because response text was not saved.

## Audit method and repository hygiene

This report was prepared by reading tracked source, tests, docs, Git metadata, local database metadata, and the saved evaluation summary. No source/configuration changes, tests, live services, external APIs, network requests, or repository publishing actions were performed. The working tree already contained an unrelated untracked `scripts/ci-loop.sh`; it was left untouched and must not be included in this report commit.
