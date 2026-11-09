# Wazuh log injection lab

This feature appends sanitized lab lines to a local file monitored by Wazuh. Wazuh reads each line and applies its installed decoders and rules. It does not create alert documents in OpenSearch itself.

Configure the same path as `SOC_AI_INJECT_PATH` in the Wazuh manager's `ossec.conf`:

```xml
<localfile>
  <location>/var/log/soc-ai-lab.log</location>
  <log_format>syslog</log_format>
</localfile>
```

Give the Wazuh manager account read permission on the file and execute/search permission on every parent directory. The upload service account needs write permission on the file and its parent directory. Do not make the file or parent directories world writable. Set `SOC_AI_INJECT_ALLOWED_DIR` to a dedicated directory containing the target file, then set `SOC_AI_INJECT_ENABLED=true` and `SOC_AI_INJECT_PATH` in the protected backend environment.

Restart the manager after changing `ossec.conf`:

```bash
sudo systemctl restart wazuh-manager
```

Check a sample line with the manager's decoder and rule engine:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Then inspect `/var/ossec/logs/alerts/alerts.json` for events that matched a rule. A line may be read and still produce no alert: an alert requires a decoder to parse the line and a rule to match the decoded fields. Add or tune local decoders and rules when the sample format has no matching rules. The API status endpoint reports file state and setup reminders only; it never claims that Wazuh has read the file.

Windows event logs are not supported as text uploads. Windows detections require a real Wazuh agent collecting Windows EventChannel data. For a lab, use a disposable Windows VM, install and enroll a Wazuh agent, and generate test events there; a text upload cannot reproduce EventChannel collection or create Windows detections.

Deleting an upload in this application removes only its platform metadata row. Alerts already created in Wazuh cannot be removed by this tool.
