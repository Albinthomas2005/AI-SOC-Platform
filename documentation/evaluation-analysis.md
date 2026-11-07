# Analysis of the 4/10 evaluation baseline

The baseline in [`evaluation.md`](evaluation.md) records pass/fail checks and
response times, but does not retain model response text. The classifications
below therefore identify which checks failed and likely causes from the
scenario definitions; exact omitted wording cannot be recovered.

| Failing scenario | Failed check(s) | Classification | Diagnosis |
|---|---|---|---|
| SYNTHETIC: Multiple failed logins | MITRE, keywords | (a), (b) | The expected `T1110` is absent according to the MITRE check. Since that id is also a required keyword, the same omission can fail both checks. The aggregate report cannot establish whether other wording was also missing. |
| SYNTHETIC: Privilege escalation | MITRE, keywords | (a), (b) | The expected `T1068` is absent according to the MITRE check and is also in `must_mention`. The scenario contains an alert description and action, but no command details; the response text is not available to identify any additional missing keyword. |
| SYNTHETIC: Suspicious PowerShell | MITRE, keywords | (a), (b) | The expected `T1059.001` is absent according to the MITRE check and is also a required keyword. The scenario says an encoded command was observed but has no command field; the report does not reveal which other terms were absent. |
| SYNTHETIC: Suspicious connection | keywords | (d), likely | MITRE `T1571` passed. The specific phrase `non-standard port` may reject valid alternatives such as `unusual port` or `uncommon port`. The baseline does not retain the output, so this synonym diagnosis is inferred from the check wording, not confirmed from a transcript. |
| SYNTHETIC: New user account | keywords | (d), likely | MITRE `T1136.001` passed. Exact phrases `new account` and `creation` may reject equivalent wording such as `account created` or `user created`. The baseline does not retain the output, so this synonym diagnosis is inferred, not confirmed. |
| SYNTHETIC: Unusual authentication | MITRE, keywords | (a), (b) | The expected `T1078` is absent according to the MITRE check and is also a required keyword. The alert already includes a successful authentication, an unusual-source description, and a source IP; no response transcript is available to pinpoint any other omitted wording. |

No scenario failed the prohibited-claims check, so there is no category (c)
failure in this baseline.

The two likely category (d) synonym groups are limited to equivalent
descriptions of the same alert detail:

- Suspicious connection: `non-standard port` accepts `nonstandard port`,
  `unusual port`, and `uncommon port`.
- New user account: `new account` accepts `new user account`, `account created`,
  and `user created`; its creation keyword accepts `created`, `create`, or
  `provisioned`.

These are inferred categories because the baseline did not retain response
text. Expected MITRE ids and prohibited-claim phrases are unchanged. Other
keyword checks remain strict until response text demonstrates a valid synonym
was rejected.

## Allowlist review for category (b)

The failed keyword checks may reflect missing alert fields, but the baseline has
no response text and cannot establish that cause. These candidate fields could
help explain the synthetic scenarios; they are not being added to the backend
allowlist:

| Scenario | Potentially useful field | Privacy risk |
|---|---|---|
| Multiple failed logins | `data.dstuser`; a minimized attempt count or time window | Usernames identify account holders; login patterns can reveal behavior and account targeting. Counts and time windows still expose activity patterns. |
| Privilege escalation | `data.command`, `data.file`, `data.srcuser` | Commands and file paths may contain credentials, tokens, personal data, or proprietary paths; usernames identify actors. |
| Suspicious PowerShell | A minimized `data.command` indicator or `data.file` | Full commands can include secrets, encoded payloads, host details, and proprietary scripts; paths can identify users and systems. Prefer a derived indicator over raw command text. |
| Unusual authentication | `data.dstuser`; carefully scoped prior-auth comparison | User identity and historical authentication behavior are personal and linkable across time, location, and systems. |

These are privacy trade-offs for future review, not evidence that the current
keyword failures were caused by missing fields. Any expansion should be
field-specific, minimized, and privacy-reviewed; no allowlist code was changed.
