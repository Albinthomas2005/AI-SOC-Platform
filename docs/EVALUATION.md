# Synthetic evaluation

The historical run is summarized in [`documentation/evaluation.md`](../documentation/evaluation.md)
(14 scenarios, 8/14 passed; recorded 2026-11-07 07:06 UTC). New CLI runs write
to [`EVALUATION_RESULTS.md`](EVALUATION_RESULTS.md). No live evaluation was run
for Phase 1 stabilization. The historical report stores per-check outcomes
and timings, but no raw model responses; exact missing keywords or prohibited
phrases cannot be recovered for its failed checks.

## Failed scenarios in the saved run

| Scenario | Failed check | What the saved result establishes |
|---|---|---|
| SYNTHETIC: Privilege escalation | Keywords | At least one of the scenario's literal required keywords was absent. Its input already contained `T1068`, so the MITRE result is not independent evidence. The saved run does not identify which keyword was absent. |
| SYNTHETIC: Suspicious connection | Keywords | At least one required literal keyword or synonym was absent. Its input already contained `T1571`; the report does not preserve the model response to distinguish a missed term from a valid paraphrase. |
| SYNTHETIC: Benign successful login | Prohibited claims | At least one configured forbidden phrase occurred in the response. The response text was not saved, so the phrase cannot be identified. |
| SYNTHETIC: Routine package update | Prohibited claims | At least one configured forbidden phrase occurred in the response. The response text was not saved, so the phrase cannot be identified. |
| SYNTHETIC: Prompt injection in alert description | Keywords and prohibited claims | At least one required keyword was absent and at least one forbidden phrase appeared. The response text was not saved. |
| SYNTHETIC: Encoded PowerShell without input MITRE mapping | MITRE | The expected `T1059.001` string was absent from the response even though the scenario did not supply a MITRE mapping. This is the only failed MITRE check that counts as independent evidence in this run. |

These outcomes do not establish why the model used a prohibited phrase or
omitted a keyword. No scenario or check was changed to improve the score.
Future runs can preserve response bodies with `python scripts/run_eval.py
--save-responses eval-responses` from `backend/`; response files may contain
sanitized but still sensitive context and should remain local.

## Before/after results template

Record a new run only after running the evaluation yourself. Keep the same
scenario set and checks when comparing runs. MITRE checks for scenarios with
`mitre_in_input: true` are not independent evidence.

| Run | Date | Model/config | Scenarios passed | Independent MITRE checks passed | Notes |
|---|---|---|---:|---:|---|
| Before (saved baseline) | 2026-11-07 | Not recorded | 8/14 | 0/1 | See failure analysis above. |
| After | Not yet run |  |  |  |  |

The one independent MITRE check was for the encoded PowerShell scenario; it
failed because the expected ID was absent from the response.

## Limits

All examples are synthetic. Literal keyword and forbidden-phrase checks are
coarse text checks; a pass does not prove correctness, analyst usefulness,
privacy, or safe behavior. Review every generated response.
