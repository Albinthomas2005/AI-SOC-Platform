# Synthetic AI Analysis Evaluation

Last run: 2026-11-07 06:46 UTC

These scenarios use synthetic, allowlisted Wazuh-style alerts. This report checks response text mechanically; it is not a clinical, security, or analyst-quality certification.

| Scenario | API | MITRE | Keywords | Prohibited claims | Time (ms) | Overall |
|---|---|---|---|---|---:|---|
| SYNTHETIC: SSH brute force | PASS | PASS | PASS | PASS | 1554 | PASS |
| SYNTHETIC: Multiple failed logins | PASS | FAIL | FAIL | PASS | 1925 | FAIL |
| SYNTHETIC: Privilege escalation | PASS | FAIL | FAIL | PASS | 1439 | FAIL |
| SYNTHETIC: File modification | PASS | PASS | PASS | PASS | 1060 | PASS |
| SYNTHETIC: Malware detection | PASS | PASS | PASS | PASS | 1268 | PASS |
| SYNTHETIC: Suspicious PowerShell | PASS | FAIL | FAIL | PASS | 1147 | FAIL |
| SYNTHETIC: Port scan | PASS | PASS | PASS | PASS | 1479 | PASS |
| SYNTHETIC: Suspicious connection | PASS | PASS | FAIL | PASS | 1610 | FAIL |
| SYNTHETIC: New user account | PASS | PASS | FAIL | PASS | 1279 | FAIL |
| SYNTHETIC: Unusual authentication | PASS | FAIL | FAIL | PASS | 6639 | FAIL |

## Limitations

- All inputs are synthetic and do not establish performance on real Wazuh telemetry.
- Keyword and phrase checks are literal, case-insensitive string checks; paraphrases can produce false failures, and a passing keyword check does not prove factual correctness.
- The harness does not validate analyst usefulness, MITRE mapping quality, privacy leakage, hallucination beyond the listed phrases, or service availability outside this run.
- Review every AI response manually. Do not use this harness as authorization for automated response actions.
