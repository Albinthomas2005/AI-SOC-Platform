
import json
import os
import sqlite3
import stat
from pathlib import Path

from database import DB_PATH, init_db

def severity_name(level):
    if level >= 12:
        return "High"
    if level >= 7:
        return "Medium"
    return "Low"


def import_alerts():
    configured_path = os.environ.get("WAZUH_ALERTS_FILE")
    if not configured_path:
        raise SystemExit(
            "WAZUH_ALERTS_FILE must be set to the Wazuh alerts JSONL file path."
        )

    alerts_file = Path(configured_path).expanduser()
    try:
        file_mode = alerts_file.stat().st_mode
    except OSError as error:
        raise SystemExit(
            f"Cannot access Wazuh alerts file from WAZUH_ALERTS_FILE: {error}"
        ) from None
    if file_mode & stat.S_IWOTH:
        raise SystemExit(
            "Refusing Wazuh alerts file because it is world-writable."
        )

    init_db()
    imported = 0
    skipped = 0

    with sqlite3.connect(DB_PATH) as db:
        # Add a separate tracking table; preserve the original alerts table.
        db.execute("""
            CREATE TABLE IF NOT EXISTS wazuh_imports (
                wazuh_id TEXT PRIMARY KEY
            )
        """)

        with alerts_file.open("r", encoding="utf-8") as source:
            for line in source:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                wazuh_id = event.get("id")
                rule = event.get("rule", {})
                timestamp = event.get("timestamp")
                description = rule.get("description", "Unknown alert")

                if not wazuh_id or not timestamp:
                    skipped += 1
                    continue

                exists = db.execute(
                    "SELECT 1 FROM wazuh_imports WHERE wazuh_id = ?",
                    (wazuh_id,),
                ).fetchone()

                if exists:
                    skipped += 1
                    continue

                level = int(rule.get("level", 0))
                severity = severity_name(level)
                source_ip = event.get("data", {}).get("srcip")

                # Keep the existing dashboard's database schema unchanged.
                db.execute("""
                    INSERT INTO alerts
                        (timestamp, severity, rule, source_ip, status)
                    VALUES (?, ?, ?, ?, 'New')
                """, (timestamp, severity, description, source_ip))

                db.execute(
                    "INSERT INTO wazuh_imports (wazuh_id) VALUES (?)",
                    (wazuh_id,),
                )
                imported += 1

    print(f"Imported: {imported}")
    print(f"Skipped:  {skipped}")


if __name__ == "__main__":
    import_alerts()
