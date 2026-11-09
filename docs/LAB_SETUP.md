# Wazuh log injection lab

This feature appends sanitized lab lines to a local file monitored by Wazuh. Wazuh reads each line and applies its installed decoders and rules. It does not create alert documents in OpenSearch itself. Linux, syslog, and web text logs are supported; Windows event logs are rejected because Windows detections require a real Wazuh agent.

Configure the same path as `SOC_AI_INJECT_PATH` in the Wazuh manager's `ossec.conf`:

```xml
<localfile>
  <location>/var/log/soc-ai-lab.log</location>
  <log_format>syslog</log_format>
</localfile>
```

Give the Wazuh manager account read permission on the file and execute/search permission on every parent directory. The upload service account needs write permission on the file and its parent directory. Do not make the file or parent directories world writable. Set `SOC_AI_INJECT_ALLOWED_DIR` to a dedicated directory containing the target file, then set `SOC_AI_INJECT_ENABLED=true` and `SOC_AI_INJECT_PATH` in the protected backend environment.

For the Dashboard's **Wazuh read confirmed** status, the backend also needs read permission on Wazuh's JSON alerts file. The default is `/var/ossec/logs/alerts/alerts.json`; set `WAZUH_ALERTS_FILE` if the manager stores it elsewhere. Grant the backend service account read access to that file and search access to its parent directories. The check scans up to the last 4 MiB of JSON lines and looks for an alert whose `location` resolves to the configured upload file and whose `timestamp` is at or after the latest upload. Confirmation is limited to 30 minutes after that upload. A log line must produce an alert through an installed decoder and matching rule; merely reading a line does not create an alert. The UI refreshes the status after an upload and when the page is reloaded.

Each upload writes its `# SOCLAB-INJECT upload=<id>` marker on a separate line before the uploaded log lines. The marker is not appended to the event text, so it cannot be parsed into fields such as `data.command`. Read confirmation uses the alert's `location` and timestamp rather than the marker, so decoder parsing of the uploaded event is unaffected.

Restart the manager after changing `ossec.conf`:

```bash
sudo systemctl restart wazuh-manager
```

Check a sample line with the manager's decoder and rule engine:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Then inspect `/var/ossec/logs/alerts/alerts.json` for events that matched a rule. A line may be read and still produce no alert: an alert requires a decoder to parse the line and a rule to match the decoded fields. Add or tune local decoders and rules when the sample format has no matching rules. If confirmation remains **no**, check the displayed reason, confirm the backend can read `WAZUH_ALERTS_FILE`, verify the alert `location` matches `SOC_AI_INJECT_PATH`, and upload again so a matching alert falls within the 30-minute window.

Windows event logs are not supported as text uploads. Windows detections require a real Wazuh agent collecting Windows EventChannel data. For a lab, use a disposable Windows VM, install and enroll a Wazuh agent, and generate test events there; a text upload cannot reproduce EventChannel collection or create Windows detections.

Deleting an upload in this application removes only its platform metadata row. Alerts already created in Wazuh cannot be removed by this tool.
