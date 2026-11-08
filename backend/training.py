"""Server-side deterministic grading for synthetic analyst training scenarios."""

import json
import copy
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import jsonify, request

import database
from mitre_validation import CATALOG_PATH, load_techniques, validate_technique_id
from groq_service import (
    GroqUnavailable,
    InvalidAIResponse,
    assess_training_scenario,
    coach_training_report,
    coach_shift_handover,
)
from privacy_filter import new_privacy_context, minimize_report_evidence, sanitize_text

DATA_DIR = Path(__file__).resolve().parents[1] / "datasets" / "training"
VISIBLE_PATH = DATA_DIR / "scenarios.json"
ANSWER_PATH = DATA_DIR / "answer-keys.json"
VERDICTS = {"true_positive", "false_positive", "benign"}
MAX_REPORT_CHARS = 12000
SHIFT_DURATION_SECONDS = 20 * 60
REPORT_SECTIONS = ("summary", "evidence", "actions", "unknowns")


def _load(path):
    with path.open(encoding="utf-8") as source:
        return json.load(source)


def _visible_scenarios():
    # This reader intentionally has no dependency on the answer-key file.
    return _load(VISIBLE_PATH)


def _has_report_sections(report):
    normalized = report.casefold()
    aliases = {
        "summary": ("summary", "assessment", "verdict"),
        "evidence": ("evidence", "observations"),
        "actions": ("actions", "investigation performed", "next steps", "recommended"),
        "unknowns": ("unknowns", "not yet verified", "limitations"),
    }
    return {section: any(term in normalized for term in terms) for section, terms in aliases.items()}


def _grade(submission, key):
    ambiguity = key.get("answer_status", "provisional").startswith("ambiguous")
    expected_verdict = None if ambiguity else key["expected_verdict"]
    expected_escalate = None if ambiguity else key["expected_escalate"]
    verdict_correct = None if expected_verdict is None else submission["verdict"] == expected_verdict
    escalation_correct = None if expected_escalate is None else submission["escalate"] == expected_escalate
    verdict_points = 0 if verdict_correct is None else (40 if verdict_correct else 0)
    escalation_points = 0 if escalation_correct is None else (20 if escalation_correct else 0)

    try:
        catalog = load_techniques(CATALOG_PATH)
    except (OSError, ValueError, json.JSONDecodeError):
        catalog = None
    submitted = list(dict.fromkeys(submission["mitre_ids"]))
    valid_ids, invalid_ids, unverified_ids = [], [], []
    for technique_id in submitted:
        status = validate_technique_id(technique_id, catalog)
        if status == "valid":
            valid_ids.append(technique_id)
        elif status in {"malformed", "invalid"}:
            invalid_ids.append(technique_id)
        else:
            unverified_ids.append(technique_id)
    accepted = set(key["accepted_mitre_ids"])
    mitre_correct = None if ambiguity or catalog is None else bool(accepted) and accepted.issubset(valid_ids)
    if not accepted and not ambiguity and catalog is not None:
        mitre_correct = len(valid_ids) == 0
    mitre_points = 0 if mitre_correct is None else (20 if mitre_correct and not invalid_ids else 0)

    sections = _has_report_sections(submission["report_text"])
    report_complete = all(sections.values())
    report_points = 20 if report_complete else 0
    applicable = [p for p in (verdict_points, escalation_points, mitre_points) if p is not None]
    score = min(100, sum(applicable) + report_points)
    mistakes = []
    if verdict_correct is False:
        mistakes.append("verdict_mismatch")
    if escalation_correct is False:
        mistakes.append("over_escalation" if submission["escalate"] else "under_escalation")
    if mitre_correct is False:
        mistakes.append("mitre_selection_mismatch")
    if not report_complete:
        mistakes.append("incomplete_report")
    return {
        "total": score,
        "maximum": 100,
        "verdict": {"points": verdict_points, "maximum": 40, "correct": verdict_correct, "expected": expected_verdict},
        "escalation": {"points": escalation_points, "maximum": 20, "correct": escalation_correct, "expected": expected_escalate},
        "mitre": {"points": mitre_points, "maximum": 20, "correct": mitre_correct, "accepted": [] if ambiguity else key["accepted_mitre_ids"], "valid": valid_ids, "invalid": invalid_ids, "unverified": unverified_ids},
        "report": {"points": report_points, "maximum": 20, "complete": report_complete, "sections": sections},
        "answer_status": key.get("answer_status", "provisional"),
        "mistakes": mistakes,
    }


def _make_shift_queue(scenarios):
    rng = random.SystemRandom()
    by_difficulty = {level: [s for s in scenarios if s["difficulty"] == level] for level in range(1, 5)}
    queue = [rng.choice(items) for items in by_difficulty.values() if items]
    selected_ids = {item["id"] for item in queue}
    remaining = [item for item in scenarios if item["id"] not in selected_ids]
    rng.shuffle(remaining)
    for scenario in remaining:
        if len(queue) >= 8:
            break
        if scenario["category"] not in {item["category"] for item in queue}:
            queue.append(scenario)
    if len(queue) < 8:
        remaining = [item for item in scenarios if item["id"] not in {q["id"] for q in queue}]
        rng.shuffle(remaining)
        queue.extend(remaining[:8 - len(queue)])
    rng.shuffle(queue)
    return queue[:8]


def _public_shift_score(score):
    clean = json.loads(json.dumps(score))
    for field in ("verdict", "escalation"):
        clean[field].pop("expected", None)
    clean["mitre"].pop("accepted", None)
    clean.pop("answer_status", None)
    return clean


def register_training_routes(app, has_valid_token):
    def authorized():
        if not has_valid_token():
            return jsonify(ok=False, error="Authentication required"), 401
        return None

    @app.get("/training/scenarios")
    def list_training_scenarios():
        denied = authorized()
        if denied:
            return denied
        scenarios = _visible_scenarios()
        if request.args.get("practice_mode", "false").lower() == "true":
            scenarios = copy.deepcopy(scenarios)
            for scenario in scenarios:
                rule = scenario.get("alert", {}).get("rule", {})
                if isinstance(rule, dict):
                    rule.pop("mitre", None)
        return jsonify(ok=True, scenarios=[{k: v for k, v in s.items() if k != "answer_key"} for s in scenarios])

    @app.get("/training/scenarios/<scenario_id>")
    def get_training_scenario(scenario_id):
        denied = authorized()
        if denied:
            return denied
        scenario = next((s for s in _visible_scenarios() if s["id"] == scenario_id), None)
        if scenario is None:
            return jsonify(ok=False, error="Scenario not found"), 404
        scenario = copy.deepcopy(scenario)
        if request.args.get("practice_mode", "false").lower() == "true":
            rule = scenario.get("alert", {}).get("rule", {})
            if isinstance(rule, dict):
                rule.pop("mitre", None)
        return jsonify(ok=True, scenario={k: v for k, v in scenario.items() if k != "answer_key"})

    @app.get("/training/scenarios/<scenario_id>/hints")
    def get_training_hints(scenario_id):
        denied = authorized()
        if denied:
            return denied
        try:
            level = int(request.args.get("level", "1"))
        except ValueError:
            return jsonify(ok=False, error="Hint level must be an integer"), 400
        user_id = request.args.get("user_id", "local-analyst")[:200]
        active_shift = database.get_active_training_shift_for_scenario(
            user_id, scenario_id, datetime.now(timezone.utc).isoformat()
        )
        if active_shift is not None:
            return jsonify(ok=False, error="Hints are disabled during a timed shift"), 403
        scenario = next((s for s in _visible_scenarios() if s["id"] == scenario_id), None)
        key = next((k for k in _load(ANSWER_PATH) if k["id"] == scenario_id), None)
        if scenario is None or key is None:
            return jsonify(ok=False, error="Scenario not found"), 404
        if not 1 <= level <= len(key["hints"]):
            return jsonify(ok=False, error="Hint level is out of range"), 400
        return jsonify(ok=True, level=level, hints=key["hints"][:level], score_impact=0)

    @app.get("/training/mitre")
    def search_training_mitre():
        denied = authorized()
        if denied:
            return denied
        query = request.args.get("q", "").strip().casefold()[:100]
        try:
            catalog = load_techniques(CATALOG_PATH)
        except (OSError, ValueError, json.JSONDecodeError):
            return jsonify(ok=True, verified=False, techniques=[])
        techniques = [{"id": tid, "name": name} for tid, name in catalog.items()
                      if not query or query in tid.casefold() or query in name.casefold()]
        return jsonify(ok=True, verified=True, techniques=techniques[:50])

    @app.get("/training/progress")
    def get_training_progress():
        denied = authorized()
        if denied:
            return denied
        user_id = request.args.get("user_id", "local-analyst")[:200]
        scenarios = {scenario["id"]: scenario for scenario in _visible_scenarios()}
        rows = database.get_training_attempts_for_user(user_id)
        category_stats = {}
        mistakes = {}
        wrong_verdict_categories = {}
        review_scenario_ids = []
        verdict_correct = verdict_graded = 0
        durations = []
        history = []
        for row in rows:
            score = json.loads(row["score_json"])
            scenario = scenarios.get(row["scenario_id"], {})
            category = scenario.get("category", "unknown")
            stats = category_stats.setdefault(category, {"attempts": 0, "verdict_correct": 0, "verdict_graded": 0})
            stats["attempts"] += 1
            correct = score.get("verdict", {}).get("correct")
            if correct is not None:
                stats["verdict_graded"] += 1
                verdict_graded += 1
                if correct:
                    stats["verdict_correct"] += 1
                    verdict_correct += 1
            for mistake in score.get("mistakes", []):
                mistakes[mistake] = mistakes.get(mistake, 0) + 1
            if correct is False:
                wrong_verdict_categories[category] = wrong_verdict_categories.get(category, 0) + 1
            try:
                submitted_at = datetime.fromisoformat(row["submitted_at"].replace("Z", "+00:00"))
                age = datetime.now(timezone.utc) - submitted_at
                latest_for_scenario = not any(item["scenario_id"] == row["scenario_id"] for item in history)
                failed = (score.get("verdict", {}).get("correct") is False or
                          score.get("escalation", {}).get("correct") is False or
                          score.get("mitre", {}).get("correct") is False or
                          score.get("report", {}).get("complete") is False)
                if latest_for_scenario and failed and age >= timedelta(days=2):
                    review_scenario_ids.append(row["scenario_id"])
            except (ValueError, TypeError):
                pass
            invalid_ids = json.loads(row["invalid_mitre_ids_json"] or "[]")
            if invalid_ids:
                mistakes["invalid_mitre_ids"] = mistakes.get("invalid_mitre_ids", 0) + len(invalid_ids)
            durations.append(row["time_spent"])
            history.append({
                "attempt_id": row["attempt_id"], "scenario_id": row["scenario_id"],
                "title": scenario.get("title", row["scenario_id"]), "category": category,
                "submitted_at": row["submitted_at"], "verdict": row["verdict"],
                "escalate": bool(row["escalate"]), "score": score.get("total", 0),
                "time_spent": row["time_spent"],
                "report_text": row["report_text"],
            })
        for stats in category_stats.values():
            stats["accuracy"] = stats["verdict_correct"] / stats["verdict_graded"] if stats["verdict_graded"] else None
        return jsonify(ok=True, progress={
            "attempt_count": len(rows),
            "per_category_accuracy": category_stats,
            "verdict_accuracy": verdict_correct / verdict_graded if verdict_graded else None,
            "verdict_correct": verdict_correct,
            "verdict_graded": verdict_graded,
            "common_mistakes": sorted(
                ({"mistake": name, "count": count} for name, count in mistakes.items()),
                key=lambda item: (-item["count"], item["mistake"]),
            ),
            "mistake_log": ([
                {"type": "over_escalation", "count": mistakes.get("over_escalation", 0), "hint": "Check whether the evidence supports urgent escalation before raising severity."},
                {"type": "missing_escalation", "count": mistakes.get("under_escalation", 0), "hint": "Look for impact, persistence, or successful access that needs a second responder."},
                *[{"type": "wrong_verdict", "category": category, "count": count, "hint": "Compare the alert outcome with corroborating evidence before deciding true positive, false positive, or benign."} for category, count in sorted(wrong_verdict_categories.items())],
                {"type": "invalid_mitre_ids", "count": mistakes.get("invalid_mitre_ids", 0), "hint": "Choose technique IDs from the local ATT&CK catalog and distinguish a rule tag from confirmed behavior."},
            ]),
            "review_scenario_ids": review_scenario_ids,
            "time_per_case": {"average_seconds": sum(durations) / len(durations) if durations else None,
                              "attempts_with_time": len(durations)},
            "attempts": history,
            "unscored_attempts": [{"attempt_id": row["attempt_id"], "case_id": row["case_id"], "submitted_at": row["submitted_at"], "verdict": row["verdict"], "report_text": row["report_text"], "time_spent": row["time_spent"], "status": "unscored - no answer key"} for row in database.get_training_unscored_attempts_for_user(user_id)],
        })

    @app.post("/training/imported-cases")
    def import_training_alert():
        denied = authorized()
        if denied:
            return denied
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or set(payload) - {"alert", "user_id"} or not isinstance(payload.get("alert"), dict):
            return jsonify(ok=False, error="A minimized Wazuh alert is required"), 400
        user_id = payload.get("user_id", "local-analyst")
        if not isinstance(user_id, str) or not user_id or len(user_id) > 200:
            return jsonify(ok=False, error="Invalid analyst identity"), 400
        alert = minimize_report_evidence(payload["alert"], privacy_context=new_privacy_context())
        if not alert:
            return jsonify(ok=False, error="Alert has no analyzable fields"), 422
        case_id = uuid.uuid4().hex
        database.save_training_imported_case(case_id, user_id, datetime.now(timezone.utc).isoformat(), alert)
        return jsonify(ok=True, case={"id": case_id, "title": "Imported Wazuh alert", "status": "unscored - no answer key", "alert": alert}), 201

    @app.post("/training/imported-cases/<case_id>/attempts")
    def submit_imported_training_attempt(case_id):
        denied = authorized()
        if denied:
            return denied
        payload = request.get_json(silent=True)
        required = {"verdict", "report_text", "time_spent"}
        if not isinstance(payload, dict) or set(payload) - (required | {"user_id"}) or not required.issubset(payload):
            return jsonify(ok=False, error="Invalid unscored attempt"), 400
        user_id = payload.get("user_id", "local-analyst")
        case = database.get_training_imported_case(case_id)
        if case is None or case["user_id"] != user_id:
            return jsonify(ok=False, error="Imported case not found"), 404
        if not isinstance(payload["verdict"], str) or payload["verdict"] not in VERDICTS or not isinstance(payload["report_text"], str) or len(payload["report_text"]) > MAX_REPORT_CHARS or type(payload["time_spent"]) is not int or not 0 <= payload["time_spent"] <= 86400:
            return jsonify(ok=False, error="Invalid unscored attempt"), 400
        scenario = {"id": case_id, "title": "Imported Wazuh alert", "alert": json.loads(case["alert_json"]), "evidence": {"log_lines": [], "context_notes": []}}
        try:
            safe_report = sanitize_text(payload["report_text"], new_privacy_context())
            coaching = coach_training_report(safe_report, scenario, "No answer key is available. Provide report-writing coaching only; do not score or infer a correct verdict.")
        except InvalidAIResponse as error:
            return jsonify(ok=False, error=f"AI coaching response failed validation: {error}"), 502
        except GroqUnavailable:
            return jsonify(ok=False, error="AI coaching is temporarily unavailable"), 503
        attempt_id = uuid.uuid4().hex
        database.save_training_unscored_attempt({"attempt_id": attempt_id, "case_id": case_id, "user_id": user_id, "submitted_at": datetime.now(timezone.utc).isoformat(), "verdict": payload["verdict"], "report_text": payload["report_text"], "time_spent": payload["time_spent"], "coaching": coaching})
        return jsonify(ok=True, attempt_id=attempt_id, status="unscored - no answer key", coaching=coaching), 201

    @app.post("/training/attempts")
    def submit_training_attempt():
        denied = authorized()
        if denied:
            return denied
        payload = request.get_json(silent=True)
        required = {"scenario_id", "verdict", "escalate", "mitre_ids", "report_text", "time_spent"}
        if not isinstance(payload, dict) or set(payload) - (required | {"user_id"}) or not required.issubset(payload):
            return jsonify(ok=False, error="Invalid training attempt"), 400
        if not isinstance(payload["verdict"], str) or payload["verdict"] not in VERDICTS or not isinstance(payload["escalate"], bool):
            return jsonify(ok=False, error="Invalid verdict or escalation value"), 400
        if not isinstance(payload["mitre_ids"], list) or len(payload["mitre_ids"]) > 20 or not all(isinstance(v, str) for v in payload["mitre_ids"]):
            return jsonify(ok=False, error="MITRE IDs must be a list of strings"), 400
        if not isinstance(payload["report_text"], str) or len(payload["report_text"]) > MAX_REPORT_CHARS:
            return jsonify(ok=False, error="Report text is invalid or too long"), 400
        if type(payload["time_spent"]) is not int or not 0 <= payload["time_spent"] <= 86400:
            return jsonify(ok=False, error="Time spent must be seconds between 0 and 86400"), 400
        scenario_id = payload["scenario_id"]
        scenario = next((s for s in _visible_scenarios() if s["id"] == scenario_id), None)
        key = next((k for k in _load(ANSWER_PATH) if k["id"] == scenario_id), None)
        if scenario is None or key is None:
            return jsonify(ok=False, error="Scenario not found"), 404
        submission = {**payload, "mitre_ids": payload["mitre_ids"]}
        score = _grade(submission, key)
        stored_score = json.loads(json.dumps(score))
        for field in ("verdict", "escalation"):
            stored_score[field].pop("expected", None)
        stored_score["mitre"].pop("accepted", None)
        stored_score.pop("answer_status", None)
        ai_assessment = None
        try:
            # The AI sees visible evidence only; the answer key is not part of
            # this function call or its prompt.
            ai_assessment = assess_training_scenario(scenario)
            try:
                catalog = load_techniques(CATALOG_PATH)
            except (OSError, ValueError, json.JSONDecodeError):
                catalog = None
            ai_assessment["mitre_validation"] = {
                technique_id: validate_technique_id(technique_id, catalog)
                for technique_id in ai_assessment["mitre_ids"]
            }
        except Exception:
            # Deterministic scoring must remain available if AI is unavailable.
            ai_assessment = None
        attempt_id = uuid.uuid4().hex
        submitted_at = datetime.now(timezone.utc).isoformat()
        disagreements = []
        if ai_assessment is not None and not score["answer_status"].startswith("ambiguous"):
            for field in ("verdict", "escalate"):
                expected = key[f"expected_{field}"]
                if ai_assessment[field] != expected:
                    disagreements.append((field, ai_assessment[field], expected))
            if set(ai_assessment["mitre_ids"]) != set(key["accepted_mitre_ids"]):
                disagreements.append(("mitre_ids", ai_assessment["mitre_ids"], key["accepted_mitre_ids"]))
        database.save_training_attempt({
            "attempt_id": attempt_id,
            "user_id": payload.get("user_id", "local-analyst"),
            "scenario_id": scenario_id,
            "submitted_at": submitted_at,
            "verdict": payload["verdict"],
            "escalate": payload["escalate"],
            "mitre_ids": payload["mitre_ids"],
            "invalid_mitre_ids": score["mitre"]["invalid"],
            "report_text": payload["report_text"],
            "time_spent": payload["time_spent"],
            "score": stored_score,
            "ai_assessment": ai_assessment,
        })
        database.save_training_disagreements(attempt_id, scenario_id, disagreements, submitted_at)
        return jsonify(ok=True, attempt_id=attempt_id, score=score,
                       feedback={"verdict": score["verdict"]["correct"], "escalation": score["escalation"]["correct"], "mitre": score["mitre"]["correct"], "report": score["report"]["sections"]},
                       explanation=key["explanation"], answer_status=key.get("answer_status", "provisional"),
                       analyst={"verdict": payload["verdict"], "escalate": payload["escalate"], "mitre_ids": payload["mitre_ids"]},
                       ai=ai_assessment,
                       expected={"verdict": score["verdict"]["expected"], "escalate": score["escalation"]["expected"], "mitre_ids": score["mitre"]["accepted"]}), 201

    @app.post("/training/attempts/<attempt_id>/coaching")
    def coach_training_attempt(attempt_id):
        denied = authorized()
        if denied:
            return denied
        if not request.is_json or not isinstance(request.get_json(silent=True), dict):
            return jsonify(ok=False, error="A JSON coaching request is required"), 400
        attempt = database.get_training_attempt(attempt_id)
        user_id = request.get_json().get("user_id", "local-analyst")
        if attempt is None or attempt["user_id"] != user_id:
            return jsonify(ok=False, error="Attempt not found"), 404
        scenario = next((s for s in _visible_scenarios() if s["id"] == attempt["scenario_id"]), None)
        key = next((k for k in _load(ANSWER_PATH) if k["id"] == attempt["scenario_id"]), None)
        if scenario is None or key is None:
            return jsonify(ok=False, error="Attempt not found"), 404
        try:
            safe_report = sanitize_text(attempt["report_text"], new_privacy_context())
            coaching = coach_training_report(safe_report, scenario, key["explanation"])
        except InvalidAIResponse as error:
            return jsonify(ok=False, error=f"AI coaching response failed validation: {error}"), 502
        except GroqUnavailable:
            return jsonify(ok=False, error="AI coaching is temporarily unavailable"), 503
        database.save_training_coaching(attempt_id, coaching)
        return jsonify(ok=True, attempt_id=attempt_id, coaching=coaching)

    @app.get("/training/ai-disagreements")
    def training_ai_disagreements():
        denied = authorized()
        if denied:
            return denied
        rows = database.get_training_ai_disagreements()
        return jsonify(ok=True, disagreements=[{
            "attempt_id": row["attempt_id"], "scenario_id": row["scenario_id"],
            "field": row["field"], "ai_value": json.loads(row["ai_value"]),
            "expected_value": json.loads(row["expected_value"]), "created_at": row["created_at"],
        } for row in rows])

    @app.post("/training/shifts")
    def start_training_shift():
        denied = authorized()
        if denied:
            return denied
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or set(payload) - {"user_id"}:
            return jsonify(ok=False, error="Invalid shift request"), 400
        user_id = payload.get("user_id", "local-analyst")
        if not isinstance(user_id, str) or not user_id or len(user_id) > 200:
            return jsonify(ok=False, error="Invalid analyst identity"), 400
        now = datetime.now(timezone.utc)
        now_text = now.isoformat()
        existing = database.get_active_training_shift(user_id, now_text)
        if existing:
            return jsonify(ok=False, error="Finish the active shift before starting another"), 409
        queue = _make_shift_queue(_visible_scenarios())
        if len(queue) != 8:
            return jsonify(ok=False, error="Not enough scenarios are available for a shift"), 503
        shift_id = uuid.uuid4().hex
        deadline = now + timedelta(seconds=SHIFT_DURATION_SECONDS)
        database.create_training_shift({
            "shift_id": shift_id, "user_id": user_id, "started_at": now_text,
            "deadline_at": deadline.isoformat(), "scenario_ids": [item["id"] for item in queue],
        })
        return jsonify(ok=True, shift_id=shift_id, started_at=now_text,
                       deadline_at=deadline.isoformat(), duration_seconds=SHIFT_DURATION_SECONDS,
                       scenarios=queue), 201

    @app.post("/training/shifts/<shift_id>/responses")
    def submit_training_shift_response(shift_id):
        denied = authorized()
        if denied:
            return denied
        payload = request.get_json(silent=True)
        required = {"scenario_id", "verdict", "escalate", "mitre_ids", "report_text", "time_spent"}
        if not isinstance(payload, dict) or set(payload) - (required | {"user_id"}) or not required.issubset(payload):
            return jsonify(ok=False, error="Invalid shift response"), 400
        user_id = payload.get("user_id", "local-analyst")
        shift = database.get_training_shift(shift_id)
        if shift is None or shift["user_id"] != user_id or shift["ended_at"] is not None:
            return jsonify(ok=False, error="Active shift not found"), 404
        now = datetime.now(timezone.utc)
        if shift["deadline_at"] <= now.isoformat():
            return jsonify(ok=False, error="Shift time has expired"), 409
        scenario_ids = json.loads(shift["scenario_ids_json"])
        if payload["scenario_id"] not in scenario_ids:
            return jsonify(ok=False, error="Scenario is not in this shift"), 400
        if any(row["scenario_id"] == payload["scenario_id"] for row in database.get_training_shift_responses(shift_id)):
            return jsonify(ok=False, error="Scenario response already recorded"), 409
        if not isinstance(payload["verdict"], str) or payload["verdict"] not in VERDICTS or not isinstance(payload["escalate"], bool):
            return jsonify(ok=False, error="Invalid verdict or escalation value"), 400
        if not isinstance(payload["mitre_ids"], list) or len(payload["mitre_ids"]) > 20 or not all(isinstance(v, str) for v in payload["mitre_ids"]):
            return jsonify(ok=False, error="MITRE IDs must be a list of strings"), 400
        if not isinstance(payload["report_text"], str) or len(payload["report_text"]) > MAX_REPORT_CHARS:
            return jsonify(ok=False, error="Report text is invalid or too long"), 400
        if type(payload["time_spent"]) is not int or not 0 <= payload["time_spent"] <= 86400:
            return jsonify(ok=False, error="Time spent must be seconds between 0 and 86400"), 400
        database.save_training_shift_response(shift_id, payload)
        return jsonify(ok=True, recorded=True, remaining=len(scenario_ids) - len(database.get_training_shift_responses(shift_id)))

    @app.post("/training/shifts/<shift_id>/complete")
    def complete_training_shift(shift_id):
        denied = authorized()
        if denied:
            return denied
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict) or set(payload) - {"user_id"}:
            return jsonify(ok=False, error="Invalid shift completion request"), 400
        user_id = payload.get("user_id", "local-analyst")
        shift = database.get_training_shift(shift_id)
        if shift is None or shift["user_id"] != user_id:
            return jsonify(ok=False, error="Shift not found"), 404
        if shift["ended_at"] is not None:
            return jsonify(ok=False, error="Shift is already complete"), 409
        scenario_ids = json.loads(shift["scenario_ids_json"])
        responses = {row["scenario_id"]: row for row in database.get_training_shift_responses(shift_id)}
        now = datetime.now(timezone.utc)
        timed_out = shift["deadline_at"] <= now.isoformat()
        if len(responses) < len(scenario_ids) and not timed_out:
            return jsonify(ok=False, error="Complete all shift cases or wait for the timer"), 409
        scenarios = {item["id"]: item for item in _visible_scenarios()}
        keys = {item["id"]: item for item in _load(ANSWER_PATH)}
        results = []
        stored_results = []
        total_points = 0
        for scenario_id in scenario_ids:
            row = responses.get(scenario_id)
            if row is None:
                results.append({"scenario_id": scenario_id, "title": scenarios[scenario_id]["title"], "score": 0, "maximum": 100, "missing": True})
                stored_results.append({"scenario_id": scenario_id, "score": 0, "maximum": 100, "missing": True})
                continue
            submission = {
                "verdict": row["verdict"], "escalate": bool(row["escalate"]),
                "mitre_ids": json.loads(row["mitre_ids_json"]), "report_text": row["report_text"],
            }
            score = _grade(submission, keys[scenario_id])
            total_points += score["total"]
            results.append({
                "scenario_id": scenario_id, "title": scenarios[scenario_id]["title"],
                "score": score["total"], "maximum": 100, "feedback": score,
                "expected": {"verdict": score["verdict"]["expected"],
                             "escalate": score["escalation"]["expected"],
                             "mitre_ids": score["mitre"]["accepted"]},
                "analyst": submission,
            })
            stored_results.append({"scenario_id": scenario_id, "score": _public_shift_score(score), "maximum": 100})
        ended_at = now.isoformat()
        summary = {
            "case_count": len(scenario_ids), "completed_count": len(responses),
            "timed_out": timed_out, "total_points": total_points,
            "maximum_points": len(scenario_ids) * 100,
            "average_score": total_points / len(scenario_ids), "cases": results,
        }
        database.finish_training_shift(shift_id, ended_at, {
            "case_count": len(scenario_ids), "completed_count": len(responses),
            "timed_out": timed_out, "total_points": total_points,
            "maximum_points": len(scenario_ids) * 100,
            "average_score": total_points / len(scenario_ids), "cases": stored_results,
        })
        return jsonify(ok=True, shift_id=shift_id, ended_at=ended_at, summary=summary)

    @app.post("/training/shifts/<shift_id>/handover")
    def submit_training_shift_handover(shift_id):
        denied = authorized()
        if denied:
            return denied
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or set(payload) - {"user_id", "note"}:
            return jsonify(ok=False, error="Invalid handover request"), 400
        user_id, note = payload.get("user_id", "local-analyst"), payload.get("note")
        shift = database.get_training_shift(shift_id)
        if shift is None or shift["user_id"] != user_id or shift["ended_at"] is None:
            return jsonify(ok=False, error="Completed shift not found"), 404
        if not isinstance(note, str) or not note.strip() or len(note) > 5000:
            return jsonify(ok=False, error="Handover note must be between 1 and 5000 characters"), 400
        safe_note = sanitize_text(note.strip(), new_privacy_context())
        try:
            coaching = coach_shift_handover(safe_note)
        except InvalidAIResponse as error:
            return jsonify(ok=False, error=f"Handover coaching response failed validation: {error}"), 502
        except GroqUnavailable:
            return jsonify(ok=False, error="Handover coaching is temporarily unavailable"), 503
        database.save_training_shift_handover(shift_id, note.strip(), coaching)
        return jsonify(ok=True, shift_id=shift_id, coaching=coaching)
