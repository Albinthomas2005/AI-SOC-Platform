# SOC Practice Guide

## Daily routine

1. Complete two or three synthetic cases. Turn on **Hide MITRE rule tags** when you want to identify techniques from the evidence.
2. Read the alert, related logs, and context before opening a hint. Hints are free and do not affect a score.
3. Use the triage checklist, then record a verdict, escalation decision, relevant techniques, and a concise report.
4. Review the feedback and mistake log. Revisit cases marked **Review**; failed cases become due again after two days.
5. Export the practice history as Markdown when you want a portable record of your write-ups.

## Weekly routine

Review category accuracy, verdict accuracy, time per case, and recurring escalation or MITRE mistakes. Repeat weak categories and compare reports for clear separation of observed evidence, actions, and unknowns. A real alert imported for practice is **unscored - no answer key**: it receives report coaching only and should not be treated as a correctness judgement.

## Triage checklist

1. What happened?
2. Who and where was involved?
3. When did it happen?
4. Was the activity expected?
5. What is the scope?
6. What is your verdict?
7. Should it be escalated?
8. What did you document?

## Reviewing draft answer keys

New scenarios are marked **draft - needs analyst review**. Before relying on their scores, a qualified analyst should independently review the evidence, expected verdict, escalation decision, accepted ATT&CK IDs, hints, and explanation. Amend the separate key only after review and record unresolved ambiguity explicitly. Do not treat draft scores as authoritative until this review is complete.

All imported-alert data is minimized and sanitized before storage. Practice scenarios use synthetic evidence. Unverified claims should be written as **not yet verified**. AI coaching is report-writing guidance only; deterministic scenario grading does not use AI.
