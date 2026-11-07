# Synthetic AI Analysis Evaluation

**Status: Not run.** The evaluation harness has not been sent to a running
backend; these scenarios are synthetic and results must be generated locally
with `backend/scripts/run_eval.py` after configuring the backend.

| Scenario | API | MITRE | Keywords | Prohibited claims | Time (ms) | Overall |
|---|---|---|---|---|---:|---|
| SYNTHETIC: SSH brute force | Not run | Not run | Not run | Not run | — | Not run |
| SYNTHETIC: Multiple failed logins | Not run | Not run | Not run | Not run | — | Not run |
| SYNTHETIC: Privilege escalation | Not run | Not run | Not run | Not run | — | Not run |
| SYNTHETIC: File modification | Not run | Not run | Not run | Not run | — | Not run |
| SYNTHETIC: Malware detection | Not run | Not run | Not run | Not run | — | Not run |
| SYNTHETIC: Suspicious PowerShell | Not run | Not run | Not run | Not run | — | Not run |
| SYNTHETIC: Port scan | Not run | Not run | Not run | Not run | — | Not run |
| SYNTHETIC: Suspicious connection | Not run | Not run | Not run | Not run | — | Not run |
| SYNTHETIC: New user account | Not run | Not run | Not run | Not run | — | Not run |
| SYNTHETIC: Unusual authentication | Not run | Not run | Not run | Not run | — | Not run |

## Limitations

- All inputs are synthetic and do not establish performance on real Wazuh telemetry.
- Keyword and phrase checks are literal, case-insensitive string checks; paraphrases can produce false failures, and passing checks do not prove factual correctness.
- The harness does not validate analyst usefulness, MITRE mapping quality, privacy leakage, hallucinations beyond the listed phrases, or service availability beyond this run.
- Review every AI response manually. Do not use this harness as authorization for automated response actions.
