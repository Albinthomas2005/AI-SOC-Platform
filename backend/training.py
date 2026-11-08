"""Server-side deterministic grading for synthetic analyst training scenarios."""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import jsonify, request

import database
from mitre_validation import CATALOG_PATH, load_techniques, validate_technique_id

DATA_DIR = Path(__file__).resolve().parents[1] / "datasets" / "training"
VISIBLE_PATH = DATA_DIR / "scenarios.json"
ANSWER_PATH = DATA_DIR / "answer-keys.json"
VERDICTS = {"true_positive", "false_positive", "benign"}
MAX_REPORT_CHARS = 12000
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
    return {
        "total": score,
        "maximum": 100,
        "verdict": {"points": verdict_points, "maximum": 40, "correct": verdict_correct, "expected": expected_verdict},
        "escalation": {"points": escalation_points, "maximum": 20, "correct": escalation_correct, "expected": expected_escalate},
        "mitre": {"points": mitre_points, "maximum": 20, "correct": mitre_correct, "accepted": [] if ambiguity else key["accepted_mitre_ids"], "valid": valid_ids, "invalid": invalid_ids, "unverified": unverified_ids},
        "report": {"points": report_points, "maximum": 20, "complete": report_complete, "sections": sections},
        "answer_status": key.get("answer_status", "provisional"),
    }


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
        return jsonify(ok=True, scenarios=[{k: v for k, v in s.items() if k != "answer_key"} for s in scenarios])

    @app.get("/training/scenarios/<scenario_id>")
    def get_training_scenario(scenario_id):
        denied = authorized()
        if denied:
            return denied
        scenario = next((s for s in _visible_scenarios() if s["id"] == scenario_id), None)
        if scenario is None:
            return jsonify(ok=False, error="Scenario not found"), 404
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
        attempt_id = uuid.uuid4().hex
        submitted_at = datetime.now(timezone.utc).isoformat()
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
        })
        return jsonify(ok=True, attempt_id=attempt_id, score=score,
                       feedback={"verdict": score["verdict"]["correct"], "escalation": score["escalation"]["correct"], "mitre": score["mitre"]["correct"], "report": score["report"]["sections"]},
                       explanation=key["explanation"], answer_status=key.get("answer_status", "provisional")), 201
