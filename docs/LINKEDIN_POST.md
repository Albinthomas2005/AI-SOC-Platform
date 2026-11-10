SOC teams handle a steady stream of alerts, while newer analysts need realistic ways to practice triage and report writing. Sending raw logs to an external AI service can also expose sensitive details.

I built the AI SOC Platform, an open-source project that connects a Wazuh Dashboard plugin to a local Flask service. It filters and minimizes alert evidence before AI provider calls, supports Groq and an optional loopback-only Ollama endpoint, and turns model output into a report draft for an analyst to review, edit, approve, or reject. A separate training workflow uses synthetic scenarios and a local MITRE ATT&CK catalog.

The principle is simple: AI drafts, the analyst decides. Privacy filtering is pattern-based, so it reduces exposure but does not guarantee anonymization. Training scenarios and answer keys remain drafts for practitioner review. Live Dashboard and end-to-end verification are still pending, and production readiness has not been established.

Repository: https://github.com/Albinthomas2005/AI-SOC-Platform

#CyberSecurity #SOC #Wazuh #SIEM #SecurityAutomation #ResponsibleAI #ThreatDetection #BlueTeam #Python
