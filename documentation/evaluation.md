# Synthetic AI Analysis Evaluation

Last run: 2026-11-07 07:06 UTC

These scenarios use synthetic, allowlisted Wazuh-style alerts. This report checks response text mechanically; it is not a clinical, security, or analyst-quality certification.

| Scenario | MITRE in input | API | MITRE | Keywords | Prohibited claims | Time (ms) | Overall |
|---|---|---|---|---|---:|---|
| SYNTHETIC: SSH brute force | yes (not independent) | PASS | PASS | PASS | PASS | 1680 | PASS |
| SYNTHETIC: Multiple failed logins | yes (not independent) | PASS | PASS | PASS | PASS | 2491 | PASS |
| SYNTHETIC: Privilege escalation | yes (not independent) | PASS | PASS | FAIL | PASS | 1376 | FAIL |
| SYNTHETIC: File modification | yes (not independent) | PASS | PASS | PASS | PASS | 1537 | PASS |
| SYNTHETIC: Malware detection | yes (not independent) | PASS | PASS | PASS | PASS | 1520 | PASS |
| SYNTHETIC: Suspicious PowerShell | yes (not independent) | PASS | PASS | PASS | PASS | 1255 | PASS |
| SYNTHETIC: Port scan | yes (not independent) | PASS | PASS | PASS | PASS | 1240 | PASS |
| SYNTHETIC: Suspicious connection | yes (not independent) | PASS | PASS | FAIL | PASS | 1120 | FAIL |
| SYNTHETIC: New user account | yes (not independent) | PASS | PASS | PASS | PASS | 1198 | PASS |
| SYNTHETIC: Unusual authentication | yes (not independent) | PASS | PASS | PASS | PASS | 1560 | PASS |
| SYNTHETIC: Benign successful login | no | PASS | N/A | PASS | FAIL | 1132 | FAIL |
| SYNTHETIC: Routine package update | no | PASS | N/A | PASS | FAIL | 926 | FAIL |
| SYNTHETIC: Prompt injection in alert description | no | PASS | N/A | FAIL | FAIL | 1500 | FAIL |
| SYNTHETIC: Encoded PowerShell without input MITRE mapping | no | PASS | FAIL | PASS | PASS | 1206 | FAIL |

## MITRE evidence context

The MITRE check for scenarios with `mitre_in_input: true` is reported for visibility but excluded from the overall result: the expected technique was already present in the alert and is not independent evidence that the model inferred it. Scenarios without an expected technique show MITRE as N/A.

Scenarios with MITRE supplied in the input:

- SYNTHETIC: SSH brute force
- SYNTHETIC: Multiple failed logins
- SYNTHETIC: Privilege escalation
- SYNTHETIC: File modification
- SYNTHETIC: Malware detection
- SYNTHETIC: Suspicious PowerShell
- SYNTHETIC: Port scan
- SYNTHETIC: Suspicious connection
- SYNTHETIC: New user account
- SYNTHETIC: Unusual authentication

## Limitations

- All inputs are synthetic and do not establish performance on real Wazuh telemetry.
- Keyword and phrase checks are literal, case-insensitive string checks; paraphrases can produce false failures, and a passing keyword check does not prove factual correctness.
- The harness does not validate analyst usefulness, MITRE mapping quality, privacy leakage, hallucination beyond the listed phrases, or service availability outside this run.
- Review every AI response manually. Do not use this harness as authorization for automated response actions.
