# Answer key review checklist

The table below is generated from the 16 scenarios marked as drafts in
`datasets/training/scenarios.json` and their matching entries in
`datasets/training/answer-keys.json`. Review each key against its visible
evidence before relying on its grading. These answer keys remain **DRAFTS
pending analyst review** until reviewed.

| ID | Title | Category | Current verdict | MITRE IDs | Reviewed | Notes |
|---|---|---|---|---|---|---|
| ssh-no-success | SSH brute force without successful login | authentication | true_positive | T1110.001 |  |  |
| ssh-success | SSH brute force followed by successful login | authentication | true_positive | T1110.001, T1078 |  |  |
| webshell-upload | Web shell upload attempt | web_attack | true_positive | T1505.003 |  |  |
| powershell-execution | Suspicious PowerShell execution | execution | true_positive | T1059.001 |  |  |
| privilege-escalation-attempt | Privilege escalation attempt | privilege_escalation | true_positive | T1068 |  |  |
| cron-persistence | Suspicious cron persistence | persistence | true_positive | T1053.003 |  |  |
| phishing-credential-use | Phishing-driven credential use | credential_access | true_positive | T1078 |  |  |
| smb-lateral-movement | Lateral movement via SMB | lateral_movement | true_positive | T1021.002 |  |  |
| exfiltration-spike | Outbound data transfer spike | exfiltration | true_positive | T1041 |  |  |
| benign-admin-maintenance | Benign administrator maintenance activity | administration | benign | — |  |  |
| routine-package-update-draft | Routine package update | administration | benign | — |  |  |
| vulnerability-scanner-false-positive | Vulnerability scanner false positive | vulnerability_scanning | false_positive | — |  |  |
| password-spray | Password spray across synthetic accounts | credential_access | true_positive | T1110.003 |  |  |
| prompt-injection-log | Prompt injection hidden in log text | input_integrity | benign | T1190 |  |  |
| noisy-monitoring-tool | Noisy but benign monitoring tool | monitoring | benign | — |  |  |
| authorized-integrity-change | Authorized file integrity maintenance | administration | benign | — |  |  |
