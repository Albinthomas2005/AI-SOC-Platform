"""Read-only hunt proposal validation and report generation."""

import json
import re
import uuid
from contextlib import closing
from datetime import datetime, timezone

from flask import jsonify, request

from database import get_connection
from groq_service import _generate
from mitre_validation import CATALOG_PATH, TECHNIQUE_ID, load_techniques
from privacy_filter import minimize_report_evidence


ALLOWED_INDEX = "wazuh-alerts-4.x-*"
ALLOWED_FIELDS = {
    "@timestamp", "timestamp", "rule.id", "rule.level", "rule.description",
    "rule.groups", "rule.mitre.id", "agent.id", "agent.name", "data.srcip",
    "data.dstip", "data.srcport", "data.dstport", "data.protocol",
    "data.action", "data.authentication_result", "data.srcuser", "data.dstuser",
}
ALLOWED_CLAUSES = {"bool", "match", "term", "range", "exists"}
MAX_QUERY_SIZE = 1000
MAX_HUNT_QUESTION_CHARS = 2000
MAX_HUNT_RESULTS = 1000


class HuntValidationError(ValueError):
    """Raised when a proposed OpenSearch query violates the read-only contract."""


def _valid_field_clause(operator, value):
    if not isinstance(value, dict) or len(value) != 1:
        raise HuntValidationError(f"{operator} must target exactly one allowlisted field")
    if operator == "exists":
        if set(value) != {"field"} or value["field"] not in ALLOWED_FIELDS:
            raise HuntValidationError("exists requires one allowlisted field name")
        return
    field, operand = next(iter(value.items()))
    if operator in {"match", "term"}:
        if field not in ALLOWED_FIELDS:
            raise HuntValidationError(f"Field is not allowlisted: {field}")
        if isinstance(operand, bool) or not isinstance(operand, (str, int, float)):
            raise HuntValidationError(f"{operator} values must be scalar")
        if isinstance(operand, str) and len(operand) > 256:
            raise HuntValidationError(f"{operator} value is too long")
        return
    if operator == "range":
        if field not in ALLOWED_FIELDS:
            raise HuntValidationError(f"Field is not allowlisted: {field}")
        if field not in {"@timestamp", "timestamp", "rule.level"}:
            raise HuntValidationError("range is only allowed for time and rule level fields")
        if not isinstance(operand, dict) or not operand or set(operand) - {"gt", "gte", "lt", "lte"}:
            raise HuntValidationError("range bounds must use gt, gte, lt, or lte")
        if not all(isinstance(bound, (str, int, float)) and not isinstance(bound, bool) for bound in operand.values()):
            raise HuntValidationError("range bounds must be scalar")


def _validate_clause(clause, depth=0):
    if depth > 5:
        raise HuntValidationError("Query nesting is too deep")
    if not isinstance(clause, dict) or len(clause) != 1:
        raise HuntValidationError("Each query clause must contain one allowed operator")
    operator, value = next(iter(clause.items()))
    if operator not in ALLOWED_CLAUSES:
        raise HuntValidationError(f"Query clause is not allowed: {operator}")
    if operator == "bool":
        if not isinstance(value, dict) or not value or set(value) - {"must", "filter", "should", "must_not"}:
            raise HuntValidationError("bool supports only must, filter, should, and must_not")
        for key, clauses in value.items():
            if not isinstance(clauses, list) or not 1 <= len(clauses) <= 10:
                raise HuntValidationError(f"bool.{key} must contain 1-10 clauses")
            for child in clauses:
                _validate_clause(child, depth + 1)
    else:
        _valid_field_clause(operator, value)


def validate_search_query(query):
    """Validate the entire read-only search envelope and DSL clause tree."""
    if not isinstance(query, dict) or set(query) != {"index", "size", "query"}:
        raise HuntValidationError("Search envelope must contain only index, size, and query")
    if query["index"] != ALLOWED_INDEX:
        raise HuntValidationError("Index is not allowlisted")
    size = query["size"]
    if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= MAX_QUERY_SIZE:
        raise HuntValidationError(f"size must be an integer from 1 to {MAX_QUERY_SIZE}")
    _validate_clause(query["query"])
    return query


def validate_mitre_ids(technique_ids, catalog_path=CATALOG_PATH):
    if not isinstance(technique_ids, list) or len(technique_ids) > 20:
        raise HuntValidationError("mitre_ids must be a list of at most 20 technique IDs")
    try:
        catalog = load_techniques(catalog_path)
    except (OSError, ValueError, json.JSONDecodeError):
        raise HuntValidationError("Local ATT&CK catalog is unavailable") from None
    mappings = []
    seen = set()
    for technique_id in technique_ids:
        if not isinstance(technique_id, str) or not TECHNIQUE_ID.fullmatch(technique_id):
            raise HuntValidationError("MITRE mapping contains a malformed technique ID")
        if technique_id not in catalog:
            raise HuntValidationError(f"MITRE technique ID is not in the local catalog: {technique_id}")
        if technique_id not in seen:
            mappings.append({"id": technique_id, "name": catalog[technique_id]})
            seen.add(technique_id)
    return mappings


def generate_hunt_proposal(question):
    prompt = f"""Convert this defensive SOC hunting question into one proposed READ-ONLY OpenSearch query.
Return strict JSON with exactly these keys: hypothesis (string), query (object), mitre_ids (array of ATT&CK IDs).
query must contain exactly index="{ALLOWED_INDEX}", size (1-1000), and query (DSL).
Allowed DSL clauses: bool with only must/filter/should/must_not arrays, and leaf clauses match, term, range, exists.
Use only these fields: {', '.join(sorted(ALLOWED_FIELDS))}.
Never use scripts, aggregations, writes, runtime fields, or unlisted fields. If no mapping is supported, use an empty mitre_ids array.
Question: {question}
"""
    generated = _generate(prompt)
    try:
        proposal = json.loads(generated)
    except (TypeError, json.JSONDecodeError):
        raise HuntValidationError("AI returned an invalid hunting proposal") from None
    if not isinstance(proposal, dict) or set(proposal) != {"hypothesis", "query", "mitre_ids"}:
        raise HuntValidationError("AI proposal has an invalid schema")
    hypothesis = proposal["hypothesis"]
    if not isinstance(hypothesis, str) or not hypothesis.strip() or len(hypothesis) > 2000:
        raise HuntValidationError("AI proposal hypothesis is invalid")
    query = validate_search_query(proposal["query"])
    mitre = validate_mitre_ids(proposal["mitre_ids"])
    return {"hypothesis": hypothesis.strip(), "query": query, "mitre": mitre}


def _safe_results(results):
    if not isinstance(results, list) or len(results) > MAX_HUNT_RESULTS:
        raise HuntValidationError(f"results must be a list of at most {MAX_HUNT_RESULTS} entries")
    cleaned = []
    for result in results:
        if not isinstance(result, dict) or not isinstance(result.get("_source"), dict):
            raise HuntValidationError("Each result must contain an _source alert object")
        alert_id = result.get("_id")
        if not isinstance(alert_id, str) or not alert_id or len(alert_id) > 512:
            raise HuntValidationError("Each result must include a valid _id")
        minimized = minimize_report_evidence(result["_source"])
        if minimized:
            cleaned.append({"_id": alert_id, "_source": minimized})
    return cleaned


def interpret_hunt_results(hypothesis, results):
    prompt = (
        "Interpret only the supplied read-only hunt results in relation to the hypothesis. "
        "Cite evidence using the supplied alert IDs. Separate observations from hypotheses and state unknowns.\n"
        + json.dumps({"hypothesis": hypothesis, "results": results}, ensure_ascii=False)
    )
    return _generate(prompt).strip()


def _user_id():
    value = request.headers.get("X-SOC-User")
    if not isinstance(value, str) or not value.strip() or len(value) > 128:
        return None
    return value.strip()


def register_hunting_routes(app, auth_check):
    @app.route("/api/hunts/proposals", methods=["POST"])
    def create_hunt_proposal():
        if not auth_check():
            return jsonify(ok=False, error="Authentication required"), 401
        user_id = _user_id()
        if user_id is None:
            return jsonify(ok=False, error="A valid signed-in user is required"), 400
        payload = request.get_json(silent=True) if request.is_json else None
        if not isinstance(payload, dict) or set(payload) != {"question"}:
            return jsonify(ok=False, error="A hunting question is required"), 400
        question = payload["question"]
        if not isinstance(question, str) or not question.strip() or len(question) > MAX_HUNT_QUESTION_CHARS:
            return jsonify(ok=False, error="question must contain 1-2000 characters"), 400
        try:
            proposal = generate_hunt_proposal(question.strip())
        except HuntValidationError as error:
            return jsonify(ok=False, error=str(error)), 422
        except Exception:
            return jsonify(ok=False, error="Hunting proposal is temporarily unavailable"), 503
        hunt_id = uuid.uuid4().hex
        created_at = datetime.now(timezone.utc).isoformat()
        with closing(get_connection()) as connection, connection:
            connection.execute(
                """INSERT INTO hunting_reports
                   (hunt_id, user_id, question, hypothesis, query_json, mitre_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    hunt_id, user_id, question.strip(), proposal["hypothesis"],
                    json.dumps(proposal["query"]), json.dumps(proposal["mitre"]), created_at,
                ),
            )
        return jsonify(ok=True, hunt_id=hunt_id, proposal=proposal), 201

    @app.route("/api/hunts/<hunt_id>/results", methods=["POST"])
    def save_hunt_results(hunt_id):
        if not auth_check():
            return jsonify(ok=False, error="Authentication required"), 401
        user_id = _user_id()
        if user_id is None:
            return jsonify(ok=False, error="A valid signed-in user is required"), 400
        if not re.fullmatch(r"[0-9a-f]{32}", hunt_id):
            return jsonify(ok=False, error="Invalid hunt ID"), 400
        payload = request.get_json(silent=True) if request.is_json else None
        if not isinstance(payload, dict) or set(payload) != {"results"}:
            return jsonify(ok=False, error="A result list is required"), 400
        try:
            results = _safe_results(payload["results"])
        except HuntValidationError as error:
            return jsonify(ok=False, error=str(error)), 400
        with closing(get_connection()) as connection, connection:
            row = connection.execute(
                "SELECT * FROM hunting_reports WHERE hunt_id = ? AND user_id = ?",
                (hunt_id, user_id),
            ).fetchone()
        if row is None:
            return jsonify(ok=False, error="Hunt proposal was not found"), 404
        try:
            interpretation = interpret_hunt_results(row["hypothesis"], results)
        except Exception:
            return jsonify(ok=False, error="Hunt interpretation is temporarily unavailable"), 503
        completed_at = datetime.now(timezone.utc).isoformat()
        with closing(get_connection()) as connection, connection:
            connection.execute(
                """UPDATE hunting_reports SET results_json = ?, interpretation = ?, completed_at = ?
                   WHERE hunt_id = ? AND user_id = ?""",
                (json.dumps(results, ensure_ascii=False), interpretation, completed_at, hunt_id, user_id),
            )
        return jsonify(ok=True, hunt_id=hunt_id, interpretation=interpretation, result_count=len(results))

    @app.route("/api/hunts/<hunt_id>", methods=["GET"])
    def get_hunt_report(hunt_id):
        if not auth_check():
            return jsonify(ok=False, error="Authentication required"), 401
        user_id = _user_id()
        if user_id is None:
            return jsonify(ok=False, error="A valid signed-in user is required"), 400
        if not re.fullmatch(r"[0-9a-f]{32}", hunt_id):
            return jsonify(ok=False, error="Invalid hunt ID"), 400
        with closing(get_connection()) as connection, connection:
            row = connection.execute(
                "SELECT * FROM hunting_reports WHERE hunt_id = ? AND user_id = ?",
                (hunt_id, user_id),
            ).fetchone()
        if row is None:
            return jsonify(ok=False, error="Hunt report was not found"), 404
        report = dict(row)
        report["query"] = json.loads(report.pop("query_json"))
        report["mitre"] = json.loads(report.pop("mitre_json"))
        report["results"] = json.loads(report.pop("results_json")) if report["results_json"] else []
        return jsonify(ok=True, report=report)
