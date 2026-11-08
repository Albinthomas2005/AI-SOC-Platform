"""Dry-run-first alert and report retention administration."""

import os
from datetime import datetime, timedelta, timezone

from flask import jsonify, request

import database
from roles_audit import request_username


def _retention_days(name, default):
    try:
        days = int(os.environ.get(name, str(default)))
    except ValueError:
        raise ValueError(f"{name} must be an integer") from None
    if not 1 <= days <= 3650:
        raise ValueError(f"{name} must be between 1 and 3650")
    return days


def _older_ids(connection, table, id_column, time_column, cutoff):
    rows = connection.execute(
        f"SELECT {id_column}, {time_column} FROM {table}"
    ).fetchall()
    old_ids = []
    for row in rows:
        try:
            parsed = datetime.fromisoformat(row[time_column].replace("Z", "+00:00"))
        except (TypeError, ValueError):
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        if parsed.astimezone(timezone.utc) < cutoff:
            old_ids.append(row[id_column])
    return old_ids


def _count_and_purge(connection, table, id_column, ids, dry_run):
    if not ids:
        return 0
    if dry_run:
        return len(ids)
    placeholders = ",".join("?" for _ in ids)
    cursor = connection.execute(
        f"DELETE FROM {table} WHERE {id_column} IN ({placeholders})", ids
    )
    return cursor.rowcount


def register_retention_routes(app, auth_check):
    @app.post("/api/admin/retention/purge")
    def purge_retained_data():
        if not auth_check():
            return jsonify(ok=False, error="Authentication required"), 401
        username = request_username()
        if username is None or database.get_soc_user_role(username) != "admin":
            return jsonify(ok=False, error="Administrator role is required"), 403
        payload = request.get_json(silent=True) if request.is_json else {}
        if not isinstance(payload, dict) or set(payload) - {"dry_run"}:
            return jsonify(ok=False, error="Invalid retention request"), 400
        dry_run = payload.get("dry_run", True)
        if not isinstance(dry_run, bool):
            return jsonify(ok=False, error="dry_run must be a boolean"), 400
        try:
            alert_days = _retention_days("SOC_AI_ALERT_RETENTION_DAYS", 90)
            report_days = _retention_days("SOC_AI_REPORT_RETENTION_DAYS", 180)
        except ValueError as error:
            return jsonify(ok=False, error=str(error)), 500

        now = datetime.now(timezone.utc)
        alert_cutoff = now - timedelta(days=alert_days)
        report_cutoff = now - timedelta(days=report_days)
        counts = {}
        with database.closing(database.get_connection()) as connection, connection:
            for table, id_column, time_column, cutoff in (
                ("alerts", "id", "timestamp", alert_cutoff),
                ("wazuh_raw_alerts", "wazuh_id", "timestamp", alert_cutoff),
                ("training_imported_cases", "case_id", "created_at", alert_cutoff),
                ("ai_analyses", "analysis_id", "created_at", report_cutoff),
                ("hunting_reports", "hunt_id", "created_at", report_cutoff),
                ("training_attempts", "attempt_id", "submitted_at", report_cutoff),
                ("training_unscored_attempts", "attempt_id", "submitted_at", report_cutoff),
            ):
                ids = _older_ids(connection, table, id_column, time_column, cutoff)
                counts[table] = _count_and_purge(connection, table, id_column, ids, dry_run)
            occurred_at = now.isoformat()
            database.append_audit_event(
                connection,
                username,
                "retention_dry_run" if dry_run else "retention_purge",
                "retention",
                "alerts-and-reports",
                occurred_at,
                {"counts": counts, "alert_days": alert_days, "report_days": report_days},
            )
        return jsonify(
            ok=True,
            dry_run=dry_run,
            retention_days={"alerts": alert_days, "reports": report_days},
            cutoff={"alerts": alert_cutoff.isoformat(), "reports": report_cutoff.isoformat()},
            counts=counts,
        )
