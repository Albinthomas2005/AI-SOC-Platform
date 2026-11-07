# Limitations and safe use

This is an educational prototype. AI output is a draft and can be incorrect,
incomplete, or overconfident. It can misread an alert, omit relevant context,
or suggest an investigation step that is not appropriate for a particular
environment. A qualified analyst must verify the alert evidence and any
recommendation before acting. This tool must not initiate response actions.

## Data sent to an AI provider

The backend allowlists selected alert fields, sanitizes known patterns, and
sends the resulting prompt and evidence to the configured provider. Generate
Report also sends the analyst's submitted notes after filtering. The current
default provider is Groq, a third-party service. Filtering is not complete
anonymization: descriptions, rule metadata, timestamps, system context, and
remaining text may identify a person, host, or organization. Review your
organization's data handling requirements before using real telemetry.

## What this project does not do

- It does not guarantee accurate detection, classification, or MITRE mapping.
- It does not establish that an alert represents a successful or malicious
  event.
- It does not correlate arbitrary historical alerts or perform a full
  investigation.
- It does not block network traffic, isolate endpoints, disable accounts, or
  execute commands.
- It does not replace Wazuh permissions, analyst review, case management, or
  incident response procedures.
- It does not guarantee privacy, compliance, or production readiness.

## Verification gaps

The backend test suite uses mocked AI behavior; it does not prove live-provider
quality. The latest saved synthetic evaluation predates current response
validation and catalog changes. The complete local MITRE catalog has not been
provided. The latest Dashboard TypeScript changes have not been built or tested
in the pinned development image, and the UI decision flow has not been tested
against a running Wazuh installation.

Use synthetic lab data until these gaps are reviewed. Keep the backend on
loopback, protect the shared service token, and never commit `.env` files,
API keys, tokens, or real alert data.
