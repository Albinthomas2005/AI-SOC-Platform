# Synthetic AI Analysis Evaluation

Last run: 2026-11-07 06:55 UTC

These scenarios use synthetic, allowlisted Wazuh-style alerts. This report checks response text mechanically; it is not a clinical, security, or analyst-quality certification.

Run the harness locally with `python backend/scripts/run_eval.py --delay 2 --save-responses eval-responses`. The token is read from `backend/.env`; response files are local-only and the directory is git-ignored.

| Scenario | MITRE in input | API | MITRE | Keywords | Prohibited claims | Time (ms) | Overall |
|---|---|---|---|---|---:|---|
| SYNTHETIC: SSH brute force | yes (not independent) | PASS | PASS | PASS | PASS | 1251 | PASS |
| SYNTHETIC: Multiple failed logins | yes (not independent) | PASS | PASS | PASS | PASS | 1464 | PASS |
| SYNTHETIC: Privilege escalation | yes (not independent) | PASS | PASS | PASS | PASS | 1320 | PASS |
| SYNTHETIC: File modification | yes (not independent) | PASS | PASS | PASS | PASS | 1566 | PASS |
| SYNTHETIC: Malware detection | yes (not independent) | PASS | PASS | PASS | PASS | 1699 | PASS |
| SYNTHETIC: Suspicious PowerShell | yes (not independent) | PASS | PASS | PASS | PASS | 1496 | PASS |
| SYNTHETIC: Port scan | yes (not independent) | PASS | PASS | PASS | PASS | 1335 | PASS |
| SYNTHETIC: Suspicious connection | yes (not independent) | PASS | PASS | PASS | PASS | 1150 | PASS |
| SYNTHETIC: New user account | yes (not independent) | PASS | PASS | PASS | PASS | 8694 | PASS |
| SYNTHETIC: Unusual authentication | yes (not independent) | PASS | PASS | PASS | PASS | 7421 | PASS |

## MITRE evidence context

This historical 10-scenario run predates the four added cases. In all ten rows above, the expected technique ID was already present in `rule.mitre.id`, so those visible MITRE matches are not independent evidence of model inference and should be excluded when interpreting the overall score. The updated harness marks these rows as input-supplied and excludes that check from its overall result.

The four additional scenarios (benign successful login, routine package update, prompt injection in an alert description, and encoded PowerShell with no input MITRE mapping) have not yet been run. Their results will appear on the next evaluation run.

## Limitations

- All inputs are synthetic and do not establish performance on real Wazuh telemetry.
- Keyword and phrase checks are literal, case-insensitive string checks; paraphrases can produce false failures, and a passing keyword check does not prove factual correctness.
- The harness does not validate analyst usefulness, MITRE mapping quality, privacy leakage, hallucination beyond the listed phrases, or service availability outside this run.
- Review every AI response manually. Do not use this harness as authorization for automated response actions.
