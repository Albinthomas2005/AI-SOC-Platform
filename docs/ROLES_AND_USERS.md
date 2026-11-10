# Roles and users

The Flask API associates the request header `X-SOC-User` with a row in the local `soc_users` table. The Dashboard plugin derives this identity from the signed-in Dashboard user and supports explicit mapping through the Dashboard server environment variable `SOC_AI_USERNAME_MAP`, formatted as JSON. For example:

```bash
SOC_AI_USERNAME_MAP='{"dashboard-login":"soc-analyst"}'
```

The mapped username must be provisioned in the backend database. The mapping does not itself grant a role. Routes check the stored role using this hierarchy:

| Minimum role | Protected scope |
|---|---|
| L1 | General analysis, report, and training API routes |
| L2 | `/api/correlations`, `/api/incidents`, and `/api/threat-intel/` |
| L3 | `/api/hunts/` |
| admin | `/api/admin/` |

Higher roles satisfy lower thresholds. An unknown or insufficient role receives 403. The Dashboard username mapping and database role must agree with the intended least-privilege access. Incidents and audit access remain pending live Dashboard mapping verification.

## Explicit provisioning

The utility `scripts/add-soc-user.py` takes a username and an explicit role and adds or updates that record in the configured SQLite database. It does not choose a username or role automatically.

```bash
backend/.venv/bin/python scripts/add-soc-user.py analyst-login L1
```

Run it only after setting the intended database path/environment and reviewing the username and role. The command above is an example and has not been run as part of this documentation work. No default SOC user is created here.

The backend also supports an explicit `SOC_AI_ADMIN_USERS` environment setting for startup role seeding. Do not set it unless each named administrator is intentionally provisioned by the operator. No administrator is created by default in this guide.
