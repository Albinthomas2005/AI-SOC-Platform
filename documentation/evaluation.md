# Synthetic AI Analysis Evaluation

Last run: 2026-11-07 06:55 UTC

These scenarios use synthetic, allowlisted Wazuh-style alerts. This report checks response text mechanically; it is not a clinical, security, or analyst-quality certification.

| Scenario | API | MITRE | Keywords | Prohibited claims | Time (ms) | Overall |
|---|---|---|---|---|---:|---|
| SYNTHETIC: SSH brute force | PASS | PASS | PASS | PASS | 1251 | PASS |
| SYNTHETIC: Multiple failed logins | PASS | PASS | PASS | PASS | 1464 | PASS |
| SYNTHETIC: Privilege escalation | PASS | PASS | PASS | PASS | 1320 | PASS |
| SYNTHETIC: File modification | PASS | PASS | PASS | PASS | 1566 | PASS |
| SYNTHETIC: Malware detection | PASS | PASS | PASS | PASS | 1699 | PASS |
| SYNTHETIC: Suspicious PowerShell | PASS | PASS | PASS | PASS | 1496 | PASS |
| SYNTHETIC: Port scan | PASS | PASS | PASS | PASS | 1335 | PASS |
| SYNTHETIC: Suspicious connection | PASS | PASS | PASS | PASS | 1150 | PASS |
| SYNTHETIC: New user account | PASS | PASS | PASS | PASS | 8694 | PASS |
| SYNTHETIC: Unusual authentication | PASS | PASS | PASS | PASS | 7421 | PASS |

## Limitations

- All inputs are synthetic and do not establish performance on real Wazuh telemetry.
- Keyword and phrase checks are literal, case-insensitive string checks; paraphrases can produce false failures, and a passing keyword check does not prove factual correctness.
- The harness does not validate analyst usefulness, MITRE mapping quality, privacy leakage, hallucination beyond the listed phrases, or service availability outside this run.
- Review every AI response manually. Do not use this harness as authorization for automated response actions.
