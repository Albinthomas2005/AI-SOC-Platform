# Example systemd deployment

This document is an example only. It does not create or install a systemd unit.
Replace `<your-user>` with the account that owns the checkout and its virtual
environment.

Before starting the backend service, confirm that no existing service is
already using port `5000`. Stop or move that service first, or set
`SOC_AI_PORT` in the backend environment file to an unused local port and
configure the dashboard controller to use that same port.

Keep `backend/.env` owned by the service user with mode `600`. It must contain
the backend provider configuration and a strong `SOC_AI_INTERNAL_TOKEN`.

```ini
[Unit]
Description=AI SOC backend
After=network.target

[Service]
Type=simple
User=<your-user>
WorkingDirectory=/home/<your-user>/AI-SOC-Platform/backend
EnvironmentFile=/home/<your-user>/AI-SOC-Platform/backend/.env
ExecStart=/home/<your-user>/AI-SOC-Platform/backend/.venv/bin/python /home/<your-user>/AI-SOC-Platform/backend/app.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

The dashboard server also needs the backend URL and same internal token. Store
them in the root-owned file `/etc/wazuh-dashboard/soc-ai.env` with mode `600`;
do not put a different token in the dashboard environment. The token must
match `SOC_AI_INTERNAL_TOKEN` in the backend environment.

```ini
# /etc/wazuh-dashboard/soc-ai.env (example placeholder only)
SOC_AI_BASE_URL=http://127.0.0.1:5000
SOC_AI_INTERNAL_TOKEN=replace-with-the-same-local-token
```

The dashboard systemd drop-in can reference the protected environment file:

```ini
[Service]
EnvironmentFile=/etc/wazuh-dashboard/soc-ai.env
```

Configure these examples for the local installation before using them, then
reload systemd and restart OpenSearch Dashboards so the process receives the
environment. The plugin reads these process environment values when handling
each request, not at module load. Keep the backend bound to loopback unless
deployment-specific network protections have been reviewed.
