"""Server-side role checks and append-only audit viewer routes."""

import json
import re
from datetime import datetime, timezone

from flask import jsonify, request

import database
from contextlib import closing


ROLE_RANK = {"L1": 1, "L2": 2, "L3": 3, "admin": 4}
ROLE_NAMES = tuple(ROLE_RANK)


def request_username():
    username = request.headers.get("X-SOC-User", "local-analyst")
    if not isinstance(username, str) or not username.strip() or len(username) > 128:
        return None
    return username.strip()


def required_role(path):
    if path.startswith("/api/admin/"):
        return "admin"
    if path.startswith("/api/hunts/"):
        return "L3"
    if path.startswith(("/api/correlations", "/api/incidents", "/api/threat-intel/")):
        return "L2"
    return "L1"


def role_allowed(role, required):
    return ROLE_RANK.get(role, 0) >= ROLE_RANK[required]


def enforce_route_access(auth_check):
    """Return an auth/role response for protected API route groups."""
    if not request.path.startswith(("/api/", "/training/")):
        return None
    if not auth_check():
        return jsonify(ok=False, error="Authentication required"), 401
    username = request_username()
    if username is None:
        return jsonify(ok=False, error="A valid signed-in user is required"), 400
    role = database.get_soc_user_role(username)
    required = required_role(request.path)
    if not role_allowed(role, required):
        return jsonify(ok=False, error=f"Role {required} or higher is required"), 403
    return None


def register_admin_routes(app, auth_check):
    def admin_required():
        if not auth_check():
            return jsonify(ok=False, error="Authentication required"), 401
        username = request_username()
        if username is None:
            return jsonify(ok=False, error="A valid signed-in user is required"), 400
        if database.get_soc_user_role(username) != "admin":
            return jsonify(ok=False, error="Administrator role is required"), 403
        return None

    @app.get("/api/admin/users")
    def list_soc_users():
        denied = admin_required()
        if denied:
            return denied
        with closing(database.get_connection()) as connection, connection:
            users = [dict(row) for row in connection.execute(
                "SELECT username, role, updated_at FROM soc_users ORDER BY username"
            )]
        return jsonify(ok=True, users=users)

    @app.put("/api/admin/users/<username>/role")
    def change_soc_user_role(username):
        denied = admin_required()
        if denied:
            return denied
        payload = request.get_json(silent=True) if request.is_json else None
        if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", username):
            return jsonify(ok=False, error="Invalid username"), 400
        if not isinstance(payload, dict) or set(payload) != {"role"} or payload.get("role") not in ROLE_NAMES:
            return jsonify(ok=False, error="role must be L1, L2, L3, or admin"), 400
        actor = request_username()
        now = datetime.now(timezone.utc).isoformat()
        with closing(database.get_connection()) as connection, connection:
            previous = connection.execute(
                "SELECT role FROM soc_users WHERE username = ?", (username,)
            ).fetchone()
            connection.execute(
                """INSERT INTO soc_users (username, role, updated_at) VALUES (?, ?, ?)
                   ON CONFLICT(username) DO UPDATE SET
                     role = excluded.role, updated_at = excluded.updated_at""",
                (username, payload["role"], now),
            )
            connection.execute(
                """INSERT INTO audit_log
                   (username, action, object_type, object_id, occurred_at, details_json)
                   VALUES (?, 'role_changed', 'user', ?, ?, ?)""",
                (actor, username, now, json.dumps({
                    "from": previous["role"] if previous else None,
                    "to": payload["role"],
                })),
            )
        return jsonify(ok=True, username=username, role=payload["role"])

    @app.get("/api/admin/audit")
    def view_audit_log():
        denied = admin_required()
        if denied:
            return denied
        try:
            limit = int(request.args.get("limit", "100"))
            offset = int(request.args.get("offset", "0"))
        except ValueError:
            return jsonify(ok=False, error="limit and offset must be integers"), 400
        if not 1 <= limit <= 500 or not 0 <= offset <= 10000:
            return jsonify(ok=False, error="limit must be 1-500 and offset 0-10000"), 400
        events = []
        for row in database.get_audit_events(limit, offset):
            event = dict(row)
            event["details"] = json.loads(event.pop("details_json"))
            events.append(event)
        return jsonify(ok=True, events=events)
