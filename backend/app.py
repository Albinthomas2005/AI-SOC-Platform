
import hmac
import json
import os
import re
import threading
import time
import uuid
from contextlib import closing
from datetime import datetime, timezone

from dotenv import load_dotenv

from flask import (
    Flask,
    jsonify,
    request,
)

from database import (
    get_connection,
    init_db,
    record_audit_event,
    save_ai_analysis,
    set_ai_analysis_decision,
)
from training import register_training_routes
from correlation import correlate_alerts
from incidents import register_incident_routes
from threat_intel import (
    RateLimitExceeded,
    extract_iocs,
    lookup_iocs,
    summarize_threat_intel,
)
from hunting import register_hunting_routes
from roles_audit import enforce_route_access, register_admin_routes
from retention import register_retention_routes
from groq_service import (
    explain_alert,
    generate_investigation_report,
    summarize_correlation,
    GroqUnavailable,
    InvalidAIResponse,
)
from privacy_filter import (
    minimize_report_evidence,
    new_privacy_context,
    sanitize_alert,
    sanitize_text,
)

app = Flask(__name__)


def configured_max_request_bytes(value=None):
    raw_value = os.environ.get("SOC_AI_MAX_REQUEST_BYTES", str(1 * 1024 * 1024)) if value is None else value
    try:
        limit = int(raw_value)
    except (TypeError, ValueError):
        raise RuntimeError("SOC_AI_MAX_REQUEST_BYTES must be an integer") from None
    if not 1024 <= limit <= 10 * 1024 * 1024:
        raise RuntimeError("SOC_AI_MAX_REQUEST_BYTES must be between 1024 and 10485760")
    return limit


app.config["MAX_CONTENT_LENGTH"] = configured_max_request_bytes()
MAX_REPORT_REQUEST_BYTES = 256 * 1024
MAX_ANALYST_NOTES_CHARS = 4000
RATE_LIMIT_BUCKETS = {}
RATE_LIMIT_LOCK = threading.Lock()


@app.errorhandler(413)
def handle_request_too_large(error):
    if request.path in (
        "/api/ai/analyze-alert",
        "/api/ai/generate-report",
    ):
        message = (
            "Report request is too large"
            if request.path == "/api/ai/generate-report"
            else "Request body is too large"
        )
        return jsonify(ok=False, error=message), 413
    return error

# Initialize the configured database when a request arrives. This keeps module
# imports side-effect free, and lets tests safely substitute a temporary DB.
@app.before_request
def initialize_database_for_request():
    init_db()


@app.before_request
def enforce_request_rate_limit():
    if not request.path.startswith(("/api/", "/training/")):
        return None
    try:
        limit = int(os.environ.get("SOC_AI_RATE_LIMIT_PER_MINUTE", "120"))
    except ValueError:
        limit = 120
    limit = max(1, min(limit, 10000))
    now = time.monotonic()
    username = request.headers.get("X-SOC-User", "local-analyst")
    key = (request.remote_addr or "unknown", username, request.endpoint or request.path)
    with RATE_LIMIT_LOCK:
        window = RATE_LIMIT_BUCKETS.get(key)
        if window is None or now - window[0] >= 60:
            RATE_LIMIT_BUCKETS[key] = [now, 1]
            return None
        if window[1] >= limit:
            return jsonify(ok=False, error="Request rate limit exceeded"), 429
        window[1] += 1
    return None


@app.before_request
def authorize_api_route():
    return enforce_route_access(has_valid_internal_token)


def has_valid_internal_token():
    expected_token = os.environ.get("SOC_AI_INTERNAL_TOKEN", "")
    authorization = request.headers.get("Authorization", "")
    scheme, separator, supplied_token = authorization.partition(" ")
    return bool(
        expected_token
        and separator
        and scheme.lower() == "bearer"
        and supplied_token
        and hmac.compare_digest(
            supplied_token.encode("utf-8"),
            expected_token.encode("utf-8"),
        )
    )


register_training_routes(app, has_valid_internal_token)
register_incident_routes(app, has_valid_internal_token)
register_hunting_routes(app, has_valid_internal_token)
register_admin_routes(app, has_valid_internal_token)
register_retention_routes(app, has_valid_internal_token)


@app.route("/api/threat-intel/lookup", methods=["POST"])
def threat_intel_lookup_api():
    if not has_valid_internal_token():
        return jsonify(ok=False, error="Authentication required"), 401
    if not request.is_json:
        return jsonify(ok=False, error="A JSON threat-intel request is required"), 400
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or set(payload) not in ({"alert"}, {"incident_id"}):
        return jsonify(ok=False, error="Provide one alert or incident_id"), 400

    if "alert" in payload:
        if not isinstance(payload["alert"], dict):
            return jsonify(ok=False, error="alert must be an object"), 400
        source = payload["alert"]
    else:
        incident_id = payload["incident_id"]
        if not isinstance(incident_id, str) or not re.fullmatch(r"[0-9a-f]{32}", incident_id):
            return jsonify(ok=False, error="Invalid incident ID"), 400
        with closing(get_connection()) as connection, connection:
            rows = connection.execute(
                """SELECT evidence_json FROM incident_evidence
                   WHERE incident_id = ? ORDER BY ordinal""", (incident_id,)
            ).fetchall()
        if not rows:
            return jsonify(ok=False, error="Incident was not found or has no evidence"), 404
        source = [json.loads(row["evidence_json"]) for row in rows]

    iocs = extract_iocs(source)[:100]
    try:
        results = lookup_iocs(iocs) if iocs else []
    except RateLimitExceeded:
        return jsonify(ok=False, error="Threat-intel provider rate limit exceeded"), 429
    summary = summarize_threat_intel(results)
    return jsonify(
        ok=True,
        iocs=iocs,
        results=results,
        summary=summary,
    )


@app.route("/api/correlations", methods=["POST"])
def correlate_alerts_api():
    if not has_valid_internal_token():
        return jsonify(ok=False, error="Authentication required"), 401

    if not request.is_json:
        return jsonify(ok=False, error="A JSON alert list is required"), 400
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or set(payload) != {"alerts"}:
        return jsonify(ok=False, error="Invalid correlation request"), 400

    try:
        result = correlate_alerts(payload["alerts"])
    except ValueError as error:
        return jsonify(ok=False, error=str(error)), 400

    summary = "No correlated alert groups were found."
    if result["groups"]:
        try:
            summary = summarize_correlation(result)
        except GroqUnavailable:
            return jsonify(
                ok=False,
                error="Correlation summary is temporarily unavailable",
                correlation=result,
            ), 503
        except Exception:
            return jsonify(
                ok=False,
                error="Correlation summary could not be completed",
                correlation=result,
            ), 500

    return jsonify(ok=True, correlation=result, summary=summary)


@app.route("/api/ai/analyze-alert", methods=["POST"])
def analyze_alert_api():
    if not has_valid_internal_token():
        return jsonify(ok=False, error="Authentication required"), 401

    if not request.is_json:
        return jsonify(ok=False, error="A JSON alert is required"), 400

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(ok=False, error="A JSON alert is required"), 400

    alert = payload.get("alert")
    if not isinstance(alert, dict) or not alert:
        return jsonify(ok=False, error="A valid alert object is required"), 400

    privacy_context = new_privacy_context()
    minimized_alert = minimize_report_evidence(
        alert, privacy_context=privacy_context
    )
    if not minimized_alert:
        return jsonify(
            ok=False,
            error="Alert has no analyzable fields",
        ), 422

    try:
        safe_alert = sanitize_alert(
            minimized_alert, privacy_context=privacy_context
        )
        analysis = explain_alert(safe_alert)
        analysis_id = uuid.uuid4().hex
        created_at = datetime.now(timezone.utc).isoformat()
        save_ai_analysis(
            analysis_id,
            created_at,
            json.dumps(safe_alert, ensure_ascii=False),
            analysis,
        )
    except InvalidAIResponse as error:
        return jsonify(
            ok=False,
            error=f"AI response failed validation: {error}",
        ), 502
    except GroqUnavailable:
        return jsonify(
            ok=False,
            error="AI analysis is temporarily unavailable",
        ), 503
    except Exception:
        return jsonify(
            ok=False,
            error="AI analysis could not be completed",
        ), 500

    return jsonify(
        ok=True,
        analysis_id=analysis_id,
        analysis=analysis,
        decision="unreviewed",
        decision_label="AI draft - not reviewed",
        decided_at=None,
    )


@app.route("/api/ai/generate-report", methods=["POST"])
def generate_report_api():
    if not has_valid_internal_token():
        return jsonify(ok=False, error="Authentication required"), 401

    if len(request.get_data(cache=True)) > MAX_REPORT_REQUEST_BYTES:
        return jsonify(ok=False, error="Report request is too large"), 413

    if not request.is_json:
        return jsonify(ok=False, error="A JSON report request is required"), 400

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or set(payload) - {"evidence", "analyst_notes"}:
        return jsonify(ok=False, error="Invalid report request"), 400

    evidence = payload.get("evidence")
    if not isinstance(evidence, dict):
        return jsonify(ok=False, error="A valid selected alert is required"), 400
    record_id = evidence.get("id")
    analyst_notes = payload.get("analyst_notes", "")
    try:
        record_id_bytes = (
            len(record_id.encode("utf-8")) if isinstance(record_id, str) else 0
        )
        if isinstance(analyst_notes, str):
            analyst_notes.encode("utf-8")
    except UnicodeEncodeError:
        return jsonify(ok=False, error="Report text must be valid UTF-8"), 400

    if (
        set(evidence) != {"index", "id", "alert"}
        or not isinstance(evidence.get("index"), str)
        or not re.fullmatch(
            r"wazuh-alerts-4\.x-[a-z0-9][a-z0-9._-]*", evidence["index"]
        )
        or not isinstance(evidence.get("id"), str)
        or not record_id
        or record_id_bytes > 512
        or not isinstance(evidence.get("alert"), dict)
    ):
        return jsonify(ok=False, error="A valid selected alert is required"), 400

    if (
        not isinstance(analyst_notes, str)
        or len(analyst_notes) > MAX_ANALYST_NOTES_CHARS
    ):
        return jsonify(ok=False, error="Analyst notes are invalid or too long"), 400

    privacy_context = new_privacy_context()
    safe_alert = minimize_report_evidence(
        evidence["alert"], privacy_context=privacy_context
    )
    if not safe_alert:
        return jsonify(ok=False, error="Alert has no analyzable fields"), 422

    safe_evidence = {
        "index": evidence["index"],
        "id": evidence["id"],
        "alert": safe_alert,
    }
    safe_notes = sanitize_text(analyst_notes, privacy_context)
    if len(json.dumps(safe_evidence, ensure_ascii=False).encode("utf-8")) > MAX_REPORT_REQUEST_BYTES:
        return jsonify(ok=False, error="Report evidence is too large"), 413

    try:
        report = generate_investigation_report(safe_alert, safe_notes)
        if not report.startswith("AI draft - not reviewed"):
            report = "AI draft - not reviewed\n\n" + report
        analysis_id = uuid.uuid4().hex
        created_at = datetime.now(timezone.utc).isoformat()
        save_ai_analysis(
            analysis_id,
            created_at,
            json.dumps(safe_alert, ensure_ascii=False),
            report,
        )
        record_audit_event(
            request.headers.get("X-SOC-User", "local-analyst"),
            "report_generated", "ai_analysis", analysis_id, created_at,
        )
    except GroqUnavailable:
        return jsonify(
            ok=False,
            error="AI report generation is temporarily unavailable",
        ), 503
    except Exception:
        return jsonify(
            ok=False,
            error="AI report generation could not be completed",
        ), 500

    return jsonify(
        ok=True,
        analysis_id=analysis_id,
        status="ai_generated_unverified",
        evidence=safe_evidence,
        report=report,
        decision="unreviewed",
        decision_label="AI draft - not reviewed",
        decided_at=None,
    )


@app.route("/api/ai/analysis/<analysis_id>/decision", methods=["POST"])
def record_analysis_decision(analysis_id):
    if not has_valid_internal_token():
        return jsonify(ok=False, error="Authentication required"), 401

    if not re.fullmatch(r"[0-9a-f]{32}", analysis_id):
        return jsonify(ok=False, error="Invalid analysis ID"), 400
    if not request.is_json:
        return jsonify(ok=False, error="A JSON analyst decision is required"), 400

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or set(payload) - {
        "decision", "note", "edited_analysis"
    }:
        return jsonify(ok=False, error="Invalid analyst decision"), 400
    decision = payload.get("decision")
    note = payload.get("note", "")
    edited_analysis = payload.get("edited_analysis")
    if (
        decision not in {"approved", "edited", "rejected"}
        or not isinstance(note, str)
        or len(note) > MAX_ANALYST_NOTES_CHARS
        or (decision == "edited" and (
            not isinstance(edited_analysis, str)
            or not edited_analysis.strip()
            or len(edited_analysis) > 65536
        ))
        or (decision != "edited" and edited_analysis is not None)
    ):
        return jsonify(ok=False, error="Invalid analyst decision"), 400

    decided_at = datetime.now(timezone.utc).isoformat()
    try:
        updated = set_ai_analysis_decision(
            analysis_id,
            decision,
            note.strip() or None,
            decided_at,
            edited_analysis.strip() if decision == "edited" else None,
        )
    except Exception:
        return jsonify(ok=False, error="Analyst decision could not be saved"), 500
    if not updated:
        return jsonify(ok=False, error="Analysis was not found"), 404
    record_audit_event(
        request.headers.get("X-SOC-User", "local-analyst"),
        "decision", "ai_analysis", analysis_id, decided_at,
        {"decision": decision},
    )

    return jsonify(
        ok=True,
        analysis_id=analysis_id,
        decision=decision,
        decision_label=f"Analyst {decision}",
        note=note.strip() or None,
        decided_at=decided_at,
        edited_analysis=edited_analysis.strip() if decision == "edited" else None,
    )


def run_app():
    # Load local configuration only when starting the service, never on import.
    load_dotenv()
    host = os.environ.get("SOC_AI_HOST", "127.0.0.1")
    port_value = os.environ.get("SOC_AI_PORT", "5000")
    allow_non_loopback = os.environ.get("SOC_AI_ALLOW_NON_LOOPBACK") == "true"

    if host not in {"127.0.0.1", "localhost", "::1"} and not allow_non_loopback:
        raise SystemExit(
            "SOC_AI_HOST must be loopback unless "
            "SOC_AI_ALLOW_NON_LOOPBACK=true is set."
        )

    try:
        port = int(port_value)
    except ValueError:
        raise SystemExit("SOC_AI_PORT must be an integer.") from None
    if not 1 <= port <= 65535:
        raise SystemExit("SOC_AI_PORT must be between 1 and 65535.")

    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    run_app()
