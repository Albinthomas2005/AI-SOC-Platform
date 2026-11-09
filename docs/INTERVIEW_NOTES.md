# Interview notes

These notes describe behavior verified in the repository source and the
backend unit suite. They do not claim a live Wazuh deployment or AI provider
was tested.

## Correlation

The backend groups alerts with a deterministic rule. It reads each alert's
timestamp and looks for a shared host, user, or source IP. Alerts that share
one of those values within the configured time window are linked. Connected
links become a group, so a short chain of related events can appear together
even when the first and last event do not share the same value directly.

The default window is 15 minutes. `SOC_AI_CORRELATION_WINDOW_MINUTES` can set
it from 1 to 1440 minutes. The grouping logic works without an AI provider.
An optional AI call summarizes a group, but it does not decide whether the
events are malicious.

## AI alert allowlist

Every alert prompt goes through one shared field selector. It keeps timestamps,
rule ID, description, level, groups and MITRE fields, `agent.name`, selected
source and destination user fields, `data.srcip`, and `location`. It leaves
out `full_log` and other unlisted alert fields. `agent.name` is represented as
a redacted host label. IP addresses and selected sensitive text are filtered
before provider calls.

Threat-intelligence extraction uses the same selected alert fields and drops
private IP addresses before looking up indicators with external providers.
This is a defined field boundary plus pattern filtering; it is not a promise
that all remaining text is anonymous. Descriptions and notes still need human
review before sending real data to a provider.

## Roles and access

The Dashboard server looks up an alert as the signed-in Dashboard user and
forwards only selected fields through a same-origin route. The browser does
not need the backend bearer token or the Groq key. The Flask service validates
its bearer token and also checks the username and role sent by the trusted
Dashboard server.

The backend role levels are L1, L2, L3, and admin. Unknown users default to
L1. Correlation, incident, and threat-intelligence routes require at least L2;
hunt routes require L3; administration routes require admin. Initial admins
can be configured with `SOC_AI_ADMIN_USERS`. Role checks are application
checks, so the Dashboard proxy and backend must be deployed as trusted
services.

## Retention

The retention endpoint counts old records first and defaults to a dry run. An
administrator must explicitly request a purge to delete records. The default
retention is 90 days for alerts and 180 days for reports, with configured
values bounded to 1 through 3650 days. The purge action records an audit event.

This is application-level cleanup, not a complete retention program. It does
not set an operating-system policy for SQLite backups, replicas, or copied
files. Operators still need to decide who can read the database and its
backups.

## Demo data and verification

`scripts/seed-demo.py` creates labeled SSH and sudo alert rows plus one
resolved incident in a separate demo database. It rejects the normal database
path. The backend tests for this behavior use temporary databases. The demo
database does not create OpenSearch alerts, so OpenSearch-backed Dashboard
panels still require records in an index the signed-in user can access.

The last recorded backend suite run completed 171 tests. Plugin Jest tests,
the Dashboard build, browser behavior, live Wazuh/OpenSearch access, and live
provider availability were not verified.
