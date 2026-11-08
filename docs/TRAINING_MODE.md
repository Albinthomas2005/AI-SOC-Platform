# Analyst Training Mode

Training Mode is a practice workflow for evidence-based triage. An analyst
reviews one synthetic Wazuh-style alert, related logs, and context notes; records
a verdict, escalation decision, MITRE ATT&CK technique IDs, and a short report;
then receives deterministic grading and report coaching. The analyst's
decisions are shown beside the AI assessment and the scenario's expected
answer after submission.

Training uses the separate `training_attempts` and
`training_ai_disagreements` SQLite tables. It does not write to `ai_analyses`
or real alert reports. Answer keys live in
`datasets/training/answer-keys.json`; visible evidence lives in
`datasets/training/scenarios.json`. Scenario listing and detail handlers read
only the visible file. The hints handler returns ordered hints without a score
penalty.

## Scenario format

Each visible scenario is one object in `scenarios.json`:

```json
{
  "id": "ssh-no-success",
  "title": "SSH brute force without successful login",
  "difficulty": 1,
  "category": "authentication",
  "status": "draft - needs analyst review",
  "alert": {
    "@timestamp": "2026-11-03T10:15:00Z",
    "rule": {
      "id": "5710",
      "level": 10,
      "description": "Synthetic repeated SSH failures",
      "groups": ["training", "synthetic", "authentication"]
    },
    "agent": {"id": "920", "name": "lab-host-15", "ip": "198.51.100.31"},
    "decoder": {"name": "synthetic-json"},
    "data": {"srcip": "198.51.100.31", "protocol": "ssh"}
  },
  "evidence": {
    "log_lines": ["Synthetic related log line"],
    "context_notes": ["Missing details are not yet verified."]
  }
}
```

An answer-key object with the same `id` is stored only in
`answer-keys.json`. It contains `expected_verdict` (`true_positive`,
`false_positive`, or `benign`), `expected_escalate`, `accepted_mitre_ids`, an
ordered `hints` list, a short `explanation`, and `answer_status`. Ambiguous
legacy cases use null verdict/escalation answers and are not graded on those
fields. Visible list/detail endpoints never load answer keys. After an attempt,
the server returns that scenario's feedback and explanation. Answer keys are
never copied into attempt rows; disagreement comparisons are stored separately.

## Writing a scenario

1. Keep every scenario synthetic. Use documentation IP ranges only
   (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), `example.com`
   domains, and invented usernames and hostnames.
2. Write realistic Wazuh alert JSON and include only evidence provided in the
   alert, log lines, and context notes. Do not use live incident details.
3. Make the difficulty 1 through 4 and choose a stable category.
4. Keep scenario text and log content as data. Prompt-injection phrases can be
   included for practice, but never treat them as instructions.
5. Write the answer key in the separate file. Distinguish observed facts from
   intent and impact. Explain what remains **not yet verified**.
6. If more than one answer is defensible from the evidence, mark the case
   ambiguous and leave undecidable expected fields unset. Do not guess.
7. For new scenarios, have the person using the tool review the answer key
   before trusting it. Every new case currently says
   `draft - needs analyst review`; its grading is provisional until review.

## Grading

Grading is deterministic and runs on the backend. Verdict is worth 40 points,
escalation 20, MITRE selection 20, and report completeness 20. The report check
looks for a summary/verdict, evidence, actions or investigation steps, and
unknowns/limitations. It checks structure, not the quality or factual accuracy
of report prose. Invalid or malformed MITRE IDs are reported. ATT&CK IDs are
verified against the generated local Enterprise ATT&CK catalog. If the catalog
is missing or unusable, their status is unverified and the MITRE field is not
scored. Catalog membership does not establish whether a technique is supported
by the scenario evidence. Hints are free and do not reduce points. AI output
never changes the deterministic score.

The AI assessment receives visible scenario evidence only. It does not receive
the answer key. Coaching runs after submission and reviews the analyst's report
against visible evidence and the revealed explanation. Both report and
scenario text are treated as untrusted in provider prompts, and provider JSON
must pass a strict schema check. AI availability does not block deterministic
grading.

## Progress and AI disagreements

Progress is calculated from stored attempts for the signed-in analyst: verdict
accuracy by category, common grading mistakes, average time per case, and
attempt history. AI disagreements are recorded separately and exposed through
the token-protected `GET /training/ai-disagreements` endpoint for evaluation.
They do not automatically edit scenarios or their answer keys.

Timed shift mode selects eight mixed scenarios and starts a 20-minute timer.
Hints are blocked for the active shift on both the page and backend. Decisions
are stored in `training_shift_responses`; final shift scores and handover
coaching are stored in `training_shifts`, separate from single-case attempts.
An incomplete shift can be scored after its deadline, with unanswered cases
scored as zero. After completion, the analyst can submit a handover note for
schema-validated AI clarity and completeness coaching.

## What is not verified or built

- All scenarios and evidence are synthetic; performance on real alerts is not
  established.
- All 16 new scenario keys need review by the person using Training Mode.
- Legacy cases marked ambiguous have no guessed verdict/escalation grading.
- MITRE IDs are checked against the local generated ATT&CK catalog, but
  technique-to-evidence mappings still need analyst review.
- The Dashboard tests and plugin build require the pinned Dashboard
  dependencies and have not been run in this workspace.
- Shift scoring and handover coaching have mocked backend tests; the plugin
  shift screen test is written but not run because Dashboard dependencies are
  missing.
- Scenario-answer quality is not independently certified; no scenario is
  auto-edited from AI disagreement data.
