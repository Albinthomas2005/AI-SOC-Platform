#!/usr/bin/env python3
"""Create clearly labeled synthetic records in a dedicated demo database."""

import argparse
import json
import sys
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
REAL_DB = (BACKEND / "soc_alerts.db").resolve()
DEMO_INCIDENT_ID = "demo-incident-ssh-bruteforce"


def _validate_demo_path(db_path):
    target = Path(db_path).expanduser().resolve()
    if target == REAL_DB or "demo" not in target.name.casefold():
        raise ValueError("Refusing to seed: the target must be a separate demo database")
    return target


def _demo_alerts():
    now = datetime(2026, 11, 8, 10, 0, tzinfo=timezone.utc)
    alerts = []
    for number in range(1, 4):
        timestamp = (now + timedelta(minutes=number)).isoformat().replace("+00:00", "Z")
        alerts.append(({
            "@timestamp": timestamp,
            "rule": {
                "id": "5710",
                "level": 10,
                "description": "[DEMO] Synthetic SSH authentication failure",
                "groups": ["demo", "sshd", "authentication_failed"],
                "mitre": {"id": ["T1110.001"], "tactic": ["Credential Access"]},
            },
            "agent": {"name": "[DEMO] linux-server"},
            "data": {"srcip": "203.0.113.50", "srcuser": "[DEMO] operator"},
            "location": "[DEMO] /var/log/auth.log",
        }, "SSH"))
    timestamp = (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
    alerts.append(({
        "@timestamp": timestamp,
        "rule": {
            "id": "5402",
            "level": 3,
            "description": "[DEMO] Sudo session changed user to root",
            "groups": ["demo", "sudo", "authentication_success"],
        },
        "agent": {"name": "[DEMO] linux-server"},
        "data": {"srcuser": "[DEMO] operator", "dstuser": "root"},
        "location": "[DEMO] /var/log/auth.log",
    }, "Sudo"))
    return [
        (f"demo-{kind.casefold()}-{number:03d}", alert)
        for number, (alert, kind) in enumerate(alerts, start=1)
    ]


def seed_demo(db_path, reset=False):
    target = _validate_demo_path(db_path)
    sys.path.insert(0, str(BACKEND))
    import database

    target.parent.mkdir(parents=True, exist_ok=True)
    original_path = database.DB_PATH
    database.DB_PATH = target
    try:
        database.init_db()
        alerts = _demo_alerts()
        created = "2026-11-08T10:10:00Z"
        if reset:
            with closing(database.get_connection()) as connection, connection:
                connection.execute("DELETE FROM incident_evidence WHERE incident_id = ?", (DEMO_INCIDENT_ID,))
                connection.execute("DELETE FROM incident_events WHERE incident_id = ?", (DEMO_INCIDENT_ID,))
                connection.execute("DELETE FROM incidents WHERE incident_id = ?", (DEMO_INCIDENT_ID,))
                connection.executemany(
                    "DELETE FROM wazuh_raw_alerts WHERE wazuh_id = ?",
                    [(alert_id,) for alert_id, _ in alerts],
                )
        with closing(database.get_connection()) as connection, connection:
            for alert_id, alert in alerts:
                connection.execute(
                    "INSERT OR REPLACE INTO wazuh_raw_alerts (wazuh_id, timestamp, raw_json) VALUES (?, ?, ?)",
                    (alert_id, alert["@timestamp"], json.dumps(alert, ensure_ascii=False)),
                )
            connection.execute(
                """INSERT OR REPLACE INTO incidents
                   (incident_id, title, category, status, assigned_analyst, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (DEMO_INCIDENT_ID, "[DEMO] Resolved SSH brute-force investigation", "demo", "Resolved", "demo-analyst", created, created),
            )
            connection.execute("DELETE FROM incident_evidence WHERE incident_id = ?", (DEMO_INCIDENT_ID,))
            connection.executemany(
                "INSERT INTO incident_evidence (incident_id, ordinal, evidence_json) VALUES (?, ?, ?)",
                [
                    (DEMO_INCIDENT_ID, ordinal, json.dumps({"alert_id": alert_id, "rule": alert["rule"], "demo": True}))
                    for ordinal, (alert_id, alert) in enumerate(alerts, start=1)
                ],
            )
        return target
    finally:
        database.DB_PATH = original_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--db-path",
        default=str(BACKEND / "soc_alerts-demo.db"),
        help="target path (must have 'demo' in its filename)",
    )
    parser.add_argument("--reset", action="store_true", help="replace only this script's demo fixtures")
    args = parser.parse_args()
    try:
        path = seed_demo(args.db_path, reset=args.reset)
    except ValueError as error:
        parser.error(str(error))
    print(f"Seeded demo data in {path}")


if __name__ == "__main__":
    main()
