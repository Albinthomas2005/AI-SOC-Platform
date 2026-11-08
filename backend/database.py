
import json
import sqlite3
from contextlib import closing
from pathlib import Path

DB_PATH = Path(__file__).parent / "soc_alerts.db"


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    """Create required tables without deleting existing data."""
    with closing(get_connection()) as connection, connection:
        # Existing dashboard summary table.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                rule TEXT NOT NULL,
                source_ip TEXT,
                status TEXT NOT NULL DEFAULT 'New'
            )
        """)

        # Existing importer tracking table.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS wazuh_imports (
                wazuh_id TEXT PRIMARY KEY
            )
        """)

        # Store original Wazuh alert JSON for the dashboard.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS wazuh_raw_alerts (
                wazuh_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                raw_json TEXT NOT NULL
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS ai_analyses (
                analysis_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                alert_json TEXT NOT NULL,
                analysis_text TEXT NOT NULL,
                decision TEXT NOT NULL DEFAULT 'unreviewed'
                    CHECK (decision IN ('unreviewed', 'approved', 'edited', 'rejected')),
                decision_note TEXT,
                decided_at TEXT,
                edited_text TEXT
            )
        """)

        # Training attempts are isolated from AI reports and contain only the
        # analyst's submission and deterministic score. Scenario answer keys
        # are deliberately never copied into this database.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS training_attempts (
                attempt_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                scenario_id TEXT NOT NULL,
                submitted_at TEXT NOT NULL,
                verdict TEXT NOT NULL,
                escalate INTEGER NOT NULL CHECK (escalate IN (0, 1)),
                mitre_ids_json TEXT NOT NULL,
                invalid_mitre_ids_json TEXT NOT NULL,
                report_text TEXT NOT NULL,
                time_spent INTEGER NOT NULL,
                score_json TEXT NOT NULL,
                ai_assessment_json TEXT,
                coaching_json TEXT
            )
        """)
        attempt_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(training_attempts)")
        }
        if "ai_assessment_json" not in attempt_columns:
            connection.execute("ALTER TABLE training_attempts ADD COLUMN ai_assessment_json TEXT")
        if "coaching_json" not in attempt_columns:
            connection.execute("ALTER TABLE training_attempts ADD COLUMN coaching_json TEXT")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS training_ai_disagreements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attempt_id TEXT NOT NULL,
                scenario_id TEXT NOT NULL,
                field TEXT NOT NULL,
                ai_value TEXT NOT NULL,
                expected_value TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(attempt_id, field)
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS training_shifts (
                shift_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                started_at TEXT NOT NULL,
                deadline_at TEXT NOT NULL,
                ended_at TEXT,
                scenario_ids_json TEXT NOT NULL,
                result_json TEXT,
                handover_note TEXT,
                handover_coaching_json TEXT
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS training_shift_responses (
                shift_id TEXT NOT NULL,
                scenario_id TEXT NOT NULL,
                verdict TEXT NOT NULL,
                escalate INTEGER NOT NULL CHECK (escalate IN (0, 1)),
                mitre_ids_json TEXT NOT NULL,
                report_text TEXT NOT NULL,
                time_spent INTEGER NOT NULL,
                PRIMARY KEY (shift_id, scenario_id)
            )
        """)


def add_alert(timestamp, severity, rule, source_ip, status="New"):
    with closing(get_connection()) as connection, connection:
        connection.execute("""
            INSERT INTO alerts
                (timestamp, severity, rule, source_ip, status)
            VALUES (?, ?, ?, ?, ?)
        """, (timestamp, severity, rule, source_ip, status))


def get_alerts():
    with closing(get_connection()) as connection, connection:
        return connection.execute("""
            SELECT * FROM alerts ORDER BY id DESC
        """).fetchall()


def get_raw_alerts(limit=100):
    """Return recent raw Wazuh alerts."""
    with closing(get_connection()) as connection, connection:
        return connection.execute("""
            SELECT wazuh_id, timestamp, raw_json
            FROM wazuh_raw_alerts
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,)).fetchall()


def get_raw_alert(wazuh_id):
    """Retrieve one original Wazuh alert by ID."""
    with closing(get_connection()) as connection, connection:
        return connection.execute("""
            SELECT wazuh_id, timestamp, raw_json
            FROM wazuh_raw_alerts
            WHERE wazuh_id = ?
        """, (wazuh_id,)).fetchone()


def save_ai_analysis(analysis_id, created_at, alert_json, analysis_text):
    """Persist sanitized evidence and an unreviewed AI draft."""
    with closing(get_connection()) as connection, connection:
        connection.execute(
            """INSERT INTO ai_analyses
                (analysis_id, created_at, alert_json, analysis_text)
                VALUES (?, ?, ?, ?)""",
            (analysis_id, created_at, alert_json, analysis_text),
        )


def set_ai_analysis_decision(
    analysis_id, decision, note, decided_at, edited_text=None
):
    """Record an analyst decision without overwriting the original AI draft."""
    with closing(get_connection()) as connection, connection:
        cursor = connection.execute(
            """UPDATE ai_analyses
               SET decision = ?, decision_note = ?, decided_at = ?, edited_text = ?
               WHERE analysis_id = ?""",
            (decision, note, decided_at, edited_text, analysis_id),
        )
        return cursor.rowcount == 1


def get_ai_analysis(analysis_id):
    with closing(get_connection()) as connection, connection:
        return connection.execute(
            "SELECT * FROM ai_analyses WHERE analysis_id = ?", (analysis_id,)
        ).fetchone()


def save_training_attempt(attempt):
    """Persist analyst work and score only; never accept an answer key."""
    with closing(get_connection()) as connection, connection:
        connection.execute(
            """INSERT INTO training_attempts
                (attempt_id, user_id, scenario_id, submitted_at, verdict,
                 escalate, mitre_ids_json, invalid_mitre_ids_json, report_text,
                 time_spent, score_json, ai_assessment_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                attempt["attempt_id"], attempt["user_id"], attempt["scenario_id"],
                attempt["submitted_at"], attempt["verdict"],
                int(attempt["escalate"]), json.dumps(attempt["mitre_ids"]),
                json.dumps(attempt["invalid_mitre_ids"]), attempt["report_text"],
                attempt["time_spent"], json.dumps(attempt["score"]),
                json.dumps(attempt.get("ai_assessment")) if attempt.get("ai_assessment") is not None else None,
            ),
        )


def get_training_attempt(attempt_id):
    with closing(get_connection()) as connection, connection:
        return connection.execute(
            "SELECT * FROM training_attempts WHERE attempt_id = ?", (attempt_id,)
        ).fetchone()


def save_training_coaching(attempt_id, coaching):
    with closing(get_connection()) as connection, connection:
        cursor = connection.execute(
            "UPDATE training_attempts SET coaching_json = ? WHERE attempt_id = ?",
            (json.dumps(coaching), attempt_id),
        )
        return cursor.rowcount == 1


def save_training_disagreements(attempt_id, scenario_id, disagreements, created_at):
    with closing(get_connection()) as connection, connection:
        for field, ai_value, expected_value in disagreements:
            connection.execute(
                """INSERT OR IGNORE INTO training_ai_disagreements
                   (attempt_id, scenario_id, field, ai_value, expected_value, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (attempt_id, scenario_id, field, json.dumps(ai_value), json.dumps(expected_value), created_at),
            )


def get_training_ai_disagreements():
    with closing(get_connection()) as connection, connection:
        return connection.execute(
            "SELECT * FROM training_ai_disagreements ORDER BY id DESC"
        ).fetchall()


def get_training_attempts_for_user(user_id):
    with closing(get_connection()) as connection, connection:
        return connection.execute(
            """SELECT attempt_id, scenario_id, submitted_at, verdict, escalate,
                      time_spent, score_json
               FROM training_attempts WHERE user_id = ? ORDER BY submitted_at DESC""",
            (user_id,),
        ).fetchall()


def create_training_shift(shift):
    with closing(get_connection()) as connection, connection:
        connection.execute(
            """INSERT INTO training_shifts
               (shift_id, user_id, started_at, deadline_at, scenario_ids_json)
               VALUES (?, ?, ?, ?, ?)""",
            (shift["shift_id"], shift["user_id"], shift["started_at"],
             shift["deadline_at"], json.dumps(shift["scenario_ids"])),
        )


def get_training_shift(shift_id):
    with closing(get_connection()) as connection, connection:
        return connection.execute(
            "SELECT * FROM training_shifts WHERE shift_id = ?", (shift_id,)
        ).fetchone()


def get_active_training_shift_for_scenario(user_id, scenario_id, now):
    with closing(get_connection()) as connection, connection:
        rows = connection.execute(
            """SELECT * FROM training_shifts WHERE user_id = ? AND ended_at IS NULL
               AND deadline_at > ?""", (user_id, now)
        ).fetchall()
        return next((row for row in rows if scenario_id in json.loads(row["scenario_ids_json"])), None)


def get_active_training_shift(user_id, now):
    with closing(get_connection()) as connection, connection:
        return connection.execute(
            """SELECT * FROM training_shifts WHERE user_id = ? AND ended_at IS NULL
               AND deadline_at > ? LIMIT 1""", (user_id, now)
        ).fetchone()


def save_training_shift_response(shift_id, response):
    with closing(get_connection()) as connection, connection:
        connection.execute(
            """INSERT OR REPLACE INTO training_shift_responses
               (shift_id, scenario_id, verdict, escalate, mitre_ids_json,
                report_text, time_spent) VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (shift_id, response["scenario_id"], response["verdict"],
             int(response["escalate"]), json.dumps(response["mitre_ids"]),
             response["report_text"], response["time_spent"]),
        )


def get_training_shift_responses(shift_id):
    with closing(get_connection()) as connection, connection:
        return connection.execute(
            "SELECT * FROM training_shift_responses WHERE shift_id = ?", (shift_id,)
        ).fetchall()


def finish_training_shift(shift_id, ended_at, result):
    with closing(get_connection()) as connection, connection:
        cursor = connection.execute(
            "UPDATE training_shifts SET ended_at = ?, result_json = ? WHERE shift_id = ? AND ended_at IS NULL",
            (ended_at, json.dumps(result), shift_id),
        )
        return cursor.rowcount == 1


def save_training_shift_handover(shift_id, note, coaching):
    with closing(get_connection()) as connection, connection:
        cursor = connection.execute(
            """UPDATE training_shifts SET handover_note = ?, handover_coaching_json = ?
               WHERE shift_id = ? AND ended_at IS NOT NULL""",
            (note, json.dumps(coaching), shift_id),
        )
        return cursor.rowcount == 1


if __name__ == "__main__":
    init_db()
    print(f"Database initialized: {DB_PATH}")
