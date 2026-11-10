# Security policy

## Reporting a vulnerability

Please do not publish secrets, real alert data, or a working exploit in an issue. Contact the repository owner, Albin Thomas, through the GitHub profile at [github.com/Albinthomas2005](https://github.com/Albinthomas2005) with a concise description and safe reproduction steps. No private security response SLA is established.

## Handling sensitive data

- Never commit `.env`, provider keys, internal tokens, real databases, or real security logs.
- Use synthetic alerts for tests and demonstrations.
- Treat privacy filtering as risk reduction, not complete anonymization.
- Keep the backend on loopback unless a deployment has separately reviewed network controls.
- Validate AI-generated findings and ATT&CK references against source evidence.
- Review the role mapping and explicit SOC role provisioning before enabling protected workflows.

Production readiness has not been established. See [the threat model](docs/THREAT_MODEL.md) for implemented controls and open risks.
