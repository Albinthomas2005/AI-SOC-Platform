"""Token-protected incident management backed by SQLite."""

import json
import re
import uuid
from contextlib import closing
from datetime import datetime, timezone

from flask import jsonify, request

import database
from database import get_connection
from privacy_filter import new_privacy_context, sanitize_alert


INCIDENT_STATUSES = (
    "New", "Investigating", "Escalated", "Contained", "Resolved", "Closed"
)
STATUS_TRANSITIONS = {
    "New": {"Investigating", "Escalated", "Closed"},
    "Investigating": {"Escalated", "Contained", "Resolved", "Closed"},
    "Escalated": {"Investigating", "Contained", "Resolved", "Closed"},
    "Contained": {"Investigating", "Resolved", "Closed"},
    "Resolved": {"Investigating", "Closed"},
    "Closed": set(),
}
MAX_INCIDENTS_PER_REQUEST = 100
MAX_NOTE_CHARS = 4000


def _now():
    return datetime.now(timezone.utc).isoformat()


def _clean_actor(value):
    if value is None:
        return "local-analyst"
    if not isinstance(value, str) or not value.strip() or len(value) > 128:
        raise ValueError("actor must be a non-empty string of at most 128 characters")
    return value.strip()


def _row_dict(row):
    return dict(row) if row is not None else None


def _event(connection, incident_id, event_type, actor, detail, created_at=None):
    connection.execute(
        """INSERT INTO incident_events
           (event_id, incident_id, event_type, actor, detail_json, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (
            uuid.uuid4().hex, incident_id, event_type, actor,
            json.dumps(detail, ensure_ascii=False), created_at or _now(),
        ),
    )


def _incident(connection, incident_id):
    return connection.execute(
        "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
    ).fetchone()


def _details(incident_id):
    with closing(get_connection()) as connection, connection:
        incident = _row_dict(_incident(connection, incident_id))
        if incident is None:
            return None
        incident["evidence"] = [
            json.loads(row["evidence_json"])
            for row in connection.execute(
                """SELECT evidence_json FROM incident_evidence
                   WHERE incident_id = ? ORDER BY ordinal""", (incident_id,)
            )
        ]
        incident["notes"] = [
            _row_dict(row) for row in connection.execute(
                """SELECT note_id, author, note, created_at FROM incident_notes
                   WHERE incident_id = ? ORDER BY created_at, note_id""", (incident_id,)
            )
        ]
        incident["decision_log"] = [
            _row_dict(row) for row in connection.execute(
                """SELECT decision_id, actor, decision, rationale, created_at
                   FROM incident_decisions WHERE incident_id = ?
                   ORDER BY created_at, decision_id""", (incident_id,)
            )
        ]
        incident["timeline"] = []
        for row in connection.execute(
            """SELECT event_id, event_type, actor, detail_json, created_at
               FROM incident_events WHERE incident_id = ?
               ORDER BY created_at, event_id""", (incident_id,)
        ):
            event = _row_dict(row)
            event["details"] = json.loads(event.pop("detail_json"))
            incident["timeline"].append(event)
        return incident


def _markdown_report(incident):
    def inline(value):
        return str(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|")

    lines = [
        f"# {inline(incident['title'])}",
        "",
        f"- Incident ID: `{inline(incident['incident_id'])}`",
        f"- Status: {inline(incident['status'])}",
        f"- Category: {inline(incident['category'] or 'Unspecified')}",
        f"- Assigned analyst: {inline(incident['assigned_analyst'] or 'Unassigned')}",
        f"- Created: {inline(incident['created_at'])}",
        "",
        "## Evidence",
    ]
    if not incident["evidence"]:
        lines.append("No evidence recorded.")
    for evidence in incident["evidence"]:
        alert_id = evidence.get("alert_id", evidence.get("_id", evidence.get("id", "unknown")))
        rule = evidence.get("rule", {})
        if not isinstance(rule, dict):
            rule = {}
        lines.append(f"- Alert `{inline(alert_id)}`; rule `{inline(rule.get('id', 'unknown'))}`")
    lines.extend(["", "## Analyst notes"])
    lines.extend(
        f"- {inline(note['created_at'])} — {inline(note['author'])}: {inline(note['note'])}"
        for note in incident["notes"]
    )
    if not incident["notes"]:
        lines.append("No analyst notes recorded.")
    lines.extend(["", "## Decision log"])
    lines.extend(
        f"- {inline(entry['created_at'])} — {inline(entry['actor'])}: "
        f"{inline(entry['decision'])} — {inline(entry['rationale'])}"
        for entry in incident["decision_log"]
    )
    if not incident["decision_log"]:
        lines.append("No analyst decisions recorded.")
    lines.append("")
    return "\n".join(lines)


def register_incident_routes(app, auth_check):
    @app.route("/api/incidents", methods=["GET", "POST"])
    def incident_collection():
        if not auth_check():
            return jsonify(ok=False, error="Authentication required"), 401
        if request.method == "GET":
            with closing(get_connection()) as connection, connection:
                incidents = [
                    _row_dict(row) for row in connection.execute(
                        "SELECT * FROM incidents ORDER BY updated_at DESC, incident_id"
                    )
                ]
            return jsonify(ok=True, incidents=incidents)

        if not request.is_json:
            return jsonify(ok=False, error="A JSON incident request is required"), 400
        payload = request.get_json(silent=True)
        allowed = {"alerts", "correlation_group", "title", "category"}
        if not isinstance(payload, dict) or set(payload) - allowed:
            return jsonify(ok=False, error="Invalid incident request"), 400
        has_alerts = "alerts" in payload
        has_group = "correlation_group" in payload
        if has_alerts == has_group:
            return jsonify(ok=False, error="Provide alerts or one correlation_group"), 400
        if has_alerts:
            evidence = payload["alerts"]
            if (
                not isinstance(evidence, list)
                or not evidence
                or len(evidence) > MAX_INCIDENTS_PER_REQUEST
                or not all(isinstance(alert, dict) for alert in evidence)
            ):
                return jsonify(ok=False, error="alerts must contain 1-100 alert objects"), 400
        else:
            group = payload["correlation_group"]
            if not isinstance(group, dict) or not isinstance(group.get("timeline"), list) or not group["timeline"]:
                return jsonify(ok=False, error="correlation_group must include a timeline"), 400
            evidence = group["timeline"]

        title = payload.get("title", "Incident")
        category = payload.get("category", "")
        try:
            actor = _clean_actor(request.headers.get("X-SOC-User", "local-analyst"))
        except ValueError as error:
            return jsonify(ok=False, error=str(error)), 400
        if not isinstance(title, str) or not title.strip() or len(title) > 200:
            return jsonify(ok=False, error="title must contain 1-200 characters"), 400
        if not isinstance(category, str) or len(category) > 100:
            return jsonify(ok=False, error="category must be at most 100 characters"), 400

        privacy_context = new_privacy_context()
        safe_evidence = [sanitize_alert(item, privacy_context=privacy_context) for item in evidence]
        incident_id = uuid.uuid4().hex
        created_at = _now()
        with closing(get_connection()) as connection, connection:
            connection.execute(
                """INSERT INTO incidents
                   (incident_id, title, category, status, assigned_analyst,
                    created_at, updated_at)
                   VALUES (?, ?, ?, 'New', NULL, ?, ?)""",
                (incident_id, title.strip(), category.strip(), created_at, created_at),
            )
            for ordinal, item in enumerate(safe_evidence):
                connection.execute(
                    """INSERT INTO incident_evidence
                       (incident_id, ordinal, evidence_json) VALUES (?, ?, ?)""",
                    (incident_id, ordinal, json.dumps(item, ensure_ascii=False)),
                )
            _event(connection, incident_id, "created", actor, {"evidence_count": len(safe_evidence)}, created_at)
            database.append_audit_event(
                connection, actor, "incident_created", "incident", incident_id,
                created_at, {"evidence_count": len(safe_evidence)},
            )
        return jsonify(ok=True, incident=_details(incident_id)), 201

    @app.route("/api/incidents/<incident_id>", methods=["GET"])
    def incident_detail(incident_id):
        if not auth_check():
            return jsonify(ok=False, error="Authentication required"), 401
        if not re.fullmatch(r"[0-9a-f]{32}", incident_id):
            return jsonify(ok=False, error="Invalid incident ID"), 400
        incident = _details(incident_id)
        if incident is None:
            return jsonify(ok=False, error="Incident was not found"), 404
        return jsonify(ok=True, incident=incident)

    @app.route("/api/incidents/<incident_id>/status", methods=["POST"])
    def update_incident_status(incident_id):
        if not auth_check():
            return jsonify(ok=False, error="Authentication required"), 401
        payload = request.get_json(silent=True) if request.is_json else None
        if not isinstance(payload, dict) or set(payload) - {"status", "note"}:
            return jsonify(ok=False, error="Invalid status update"), 400
        next_status = payload.get("status")
        note = payload.get("note", "")
        try:
            actor = _clean_actor(request.headers.get("X-SOC-User", "local-analyst"))
        except ValueError as error:
            return jsonify(ok=False, error=str(error)), 400
        if next_status not in INCIDENT_STATUSES or not isinstance(note, str) or len(note) > MAX_NOTE_CHARS:
            return jsonify(ok=False, error="Invalid status or note"), 400
        now = _now()
        with closing(get_connection()) as connection, connection:
            current = _incident(connection, incident_id)
            if current is None:
                return jsonify(ok=False, error="Incident was not found"), 404
            previous = current["status"]
            if next_status not in STATUS_TRANSITIONS[previous]:
                return jsonify(ok=False, error=f"Invalid status transition: {previous} -> {next_status}"), 409
            connection.execute(
                "UPDATE incidents SET status = ?, updated_at = ? WHERE incident_id = ?",
                (next_status, now, incident_id),
            )
            database.append_audit_event(
                connection, actor, "status_changed", "incident", incident_id, now,
                {"from": previous, "to": next_status},
            )
            _event(connection, incident_id, "status_changed", actor, {
                "from": previous, "to": next_status, "note": note.strip(),
            }, now)
        return jsonify(ok=True, incident=_details(incident_id))

    @app.route("/api/incidents/<incident_id>/assignment", methods=["POST"])
    def assign_incident(incident_id):
        if not auth_check():
            return jsonify(ok=False, error="Authentication required"), 401
        payload = request.get_json(silent=True) if request.is_json else None
        if not isinstance(payload, dict) or set(payload) != {"analyst"}:
            return jsonify(ok=False, error="Invalid assignment request"), 400
        analyst = payload["analyst"]
        try:
            actor = _clean_actor(request.headers.get("X-SOC-User", "local-analyst"))
        except ValueError as error:
            return jsonify(ok=False, error=str(error)), 400
        if analyst is not None and (
            not isinstance(analyst, str) or not analyst.strip() or len(analyst) > 128
        ):
            return jsonify(ok=False, error="analyst must be null or a non-empty string of at most 128 characters"), 400
        analyst = analyst.strip() if isinstance(analyst, str) else None
        now = _now()
        with closing(get_connection()) as connection, connection:
            if _incident(connection, incident_id) is None:
                return jsonify(ok=False, error="Incident was not found"), 404
            connection.execute(
                "UPDATE incidents SET assigned_analyst = ?, updated_at = ? WHERE incident_id = ?",
                (analyst, now, incident_id),
            )
            database.append_audit_event(
                connection, actor, "assigned", "incident", incident_id, now,
                {"analyst": analyst},
            )
            _event(connection, incident_id, "assigned", actor, {"analyst": analyst}, now)
        return jsonify(ok=True, incident=_details(incident_id))

    @app.route("/api/incidents/<incident_id>/notes", methods=["POST"])
    def add_incident_note(incident_id):
        if not auth_check():
            return jsonify(ok=False, error="Authentication required"), 401
        payload = request.get_json(silent=True) if request.is_json else None
        if not isinstance(payload, dict) or set(payload) != {"note"}:
            return jsonify(ok=False, error="Invalid incident note"), 400
        note = payload.get("note")
        author = request.headers.get("X-SOC-User", "local-analyst")
        if not isinstance(author, str) or not author.strip() or len(author) > 128:
            return jsonify(ok=False, error="author must be a non-empty string of at most 128 characters"), 400
        if not isinstance(note, str) or not note.strip() or len(note) > MAX_NOTE_CHARS:
            return jsonify(ok=False, error="note must contain 1-4000 characters"), 400
        now = _now()
        note_id = uuid.uuid4().hex
        with closing(get_connection()) as connection, connection:
            if _incident(connection, incident_id) is None:
                return jsonify(ok=False, error="Incident was not found"), 404
            connection.execute(
                """INSERT INTO incident_notes
                   (note_id, incident_id, author, note, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (note_id, incident_id, author.strip(), note.strip(), now),
            )
            connection.execute(
                "UPDATE incidents SET updated_at = ? WHERE incident_id = ?",
                (now, incident_id),
            )
            database.append_audit_event(
                connection, author.strip(), "note_added", "incident", incident_id,
                now, {"note_id": note_id},
            )
            _event(connection, incident_id, "note_added", author.strip(), {"note_id": note_id}, now)
        return jsonify(ok=True, note={"note_id": note_id, "author": author.strip(), "note": note.strip(), "created_at": now}), 201

    @app.route("/api/incidents/<incident_id>/decisions", methods=["POST"])
    def add_incident_decision(incident_id):
        if not auth_check():
            return jsonify(ok=False, error="Authentication required"), 401
        payload = request.get_json(silent=True) if request.is_json else None
        if not isinstance(payload, dict) or set(payload) - {"decision", "rationale"}:
            return jsonify(ok=False, error="Invalid incident decision"), 400
        decision = payload.get("decision")
        rationale = payload.get("rationale", "")
        try:
            actor = _clean_actor(request.headers.get("X-SOC-User", "local-analyst"))
        except ValueError as error:
            return jsonify(ok=False, error=str(error)), 400
        if not isinstance(decision, str) or not decision.strip() or len(decision) > 100:
            return jsonify(ok=False, error="decision must contain 1-100 characters"), 400
        if not isinstance(rationale, str) or len(rationale) > MAX_NOTE_CHARS:
            return jsonify(ok=False, error="rationale must be at most 4000 characters"), 400
        decision_id = uuid.uuid4().hex
        now = _now()
        with closing(get_connection()) as connection, connection:
            if _incident(connection, incident_id) is None:
                return jsonify(ok=False, error="Incident was not found"), 404
            connection.execute(
                """INSERT INTO incident_decisions
                   (decision_id, incident_id, actor, decision, rationale, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (decision_id, incident_id, actor, decision.strip(), rationale.strip(), now),
            )
            connection.execute(
                "UPDATE incidents SET updated_at = ? WHERE incident_id = ?",
                (now, incident_id),
            )
            database.append_audit_event(
                connection, actor, "decision", "incident", incident_id, now,
                {"decision": decision.strip()},
            )
            _event(connection, incident_id, "decision_recorded", actor, {
                "decision_id": decision_id, "decision": decision.strip(),
            }, now)
        return jsonify(ok=True, decision={
            "decision_id": decision_id, "decision": decision.strip(),
            "rationale": rationale.strip(), "actor": actor, "created_at": now,
        }), 201

    @app.route("/api/incidents/<incident_id>/report", methods=["GET"])
    def incident_report(incident_id):
        if not auth_check():
            return jsonify(ok=False, error="Authentication required"), 401
        incident = _details(incident_id)
        if incident is None:
            return jsonify(ok=False, error="Incident was not found"), 404
        return jsonify(ok=True, report=_markdown_report(incident))
