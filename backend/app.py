
import hmac
import json
import os
import re
import uuid
from datetime import datetime, timezone

from dotenv import load_dotenv

# Load environment variables before importing the AI service so it sees the
# configured model and credentials.
load_dotenv()

from flask import (
    Flask,
    jsonify,
    request,
)

from database import init_db, save_ai_analysis, set_ai_analysis_decision
from groq_service import (
    explain_alert,
    generate_investigation_report,
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
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024
MAX_REPORT_REQUEST_BYTES = 256 * 1024
MAX_ANALYST_NOTES_CHARS = 4000


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

# Initialize the local database.
init_db()


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
