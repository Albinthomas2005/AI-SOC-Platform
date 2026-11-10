#!/usr/bin/env bash
set -u

BASE_URL="http://127.0.0.1:${SOC_AI_PORT:-5000}"
body_file="$(mktemp)"
shift_file="$(mktemp)"
trap 'rm -f "$body_file" "$shift_file"' EXIT
token="${SOC_AI_INTERNAL_TOKEN:-}"
user_id="smoke-test-$$"
failures=0
LAST_OK=0
HTTP_STATUS=000

request() {
  local method="$1" path="$2" payload="${3:-}"
  if [[ "$method" == "GET" ]]; then
    HTTP_STATUS="$(curl --silent --show-error --connect-timeout 3 \
      --output "$body_file" --write-out '%{http_code}' \
      --header "Authorization: Bearer ${token}" "${BASE_URL}${path}")" || HTTP_STATUS=000
  else
    HTTP_STATUS="$(curl --silent --show-error --connect-timeout 3 --max-time 55 \
      --output "$body_file" --write-out '%{http_code}' \
      --header "Authorization: Bearer ${token}" \
      --header 'Content-Type: application/json' \
      --data "$payload" "${BASE_URL}${path}")" || HTTP_STATUS=000
  fi
}

check_response() {
  local label="$1" method="$2" path="$3" payload="$4" expected="$5" check="$6"
  request "$method" "$path" "$payload"
  if [[ "$HTTP_STATUS" == "$expected" ]] && python3 - "$body_file" "$check" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as source:
        body = json.load(source)
except (OSError, json.JSONDecodeError):
    raise SystemExit(1)

check = sys.argv[2]
progress = body.get("progress") if isinstance(body, dict) else None
summary = body.get("summary") if isinstance(body, dict) else None
valid = isinstance(body, dict) and body.get("ok") is True
if check == "scenarios":
    valid = valid and isinstance(body.get("scenarios"), list)
elif check == "progress":
    valid = valid and isinstance(progress, dict)
elif check == "export":
    valid = (valid and isinstance(progress, dict)
             and isinstance(progress.get("attempts"), list)
             and isinstance(progress.get("unscored_attempts"), list))
elif check == "report":
    valid = (valid and isinstance(body.get("analysis_id"), str)
             and isinstance(body.get("report"), str) and bool(body["report"].strip()))
elif check == "shift_started":
    valid = (valid and isinstance(body.get("shift_id"), str)
             and isinstance(body.get("scenarios"), list) and len(body["scenarios"]) == 8)
elif check == "shift_response":
    valid = valid and body.get("recorded") is True
elif check == "shift_complete":
    valid = (valid and isinstance(summary, dict) and summary.get("case_count") == 8
             and summary.get("completed_count") == 8)
elif check == "handover":
    coaching = body.get("coaching") if isinstance(body, dict) else None
    valid = valid and isinstance(coaching, dict) and all(
        isinstance(coaching.get(key), str) and coaching[key].strip()
        for key in ("clarity_feedback", "completeness_feedback", "next_shift_practice")
    )
raise SystemExit(0 if valid else 1)
PY
  then
    echo "PASS - ${label} (${method} ${path})"
    LAST_OK=1
  else
    echo "FAIL - ${label} (${method} ${path}, HTTP ${HTTP_STATUS})"
    failures=$((failures + 1))
    LAST_OK=0
  fi
}

probe_endpoint() {
  local label="$1" method="$2" path="$3" payload="$4" allowed="$5"
  request "$method" "$path" "$payload"
  case " ${allowed} " in
    *" ${HTTP_STATUS} "*) echo "PASS - ${label} (${method} ${path}, HTTP ${HTTP_STATUS})" ;;
    *) echo "FAIL - ${label} (${method} ${path}, HTTP ${HTTP_STATUS}; expected ${allowed})"; failures=$((failures + 1)) ;;
  esac
}

check_response "scenarios" GET "/training/scenarios" "" 200 scenarios
check_response "progress" GET "/training/progress" "" 200 progress
check_response "export data (client-side Markdown source)" GET "/training/progress" "" 200 export

report_payload='{"evidence":{"index":"wazuh-alerts-4.x-smoke-test","id":"synthetic-smoke-alert","alert":{"@timestamp":"2026-11-08T00:00:00Z","rule":{"id":"SMOKE-1","level":3,"description":"Synthetic local smoke test alert"},"data":{"protocol":"synthetic","action":"smoke test"}}},"analyst_notes":"Synthetic smoke test only; no real alert data."}'
check_response "report generation" POST "/api/ai/generate-report" "$report_payload" 200 report

shift_payload="{\"user_id\":\"${user_id}\"}"
check_response "shift start" POST "/training/shifts" "$shift_payload" 201 shift_started
if [[ "$LAST_OK" == "1" ]]; then
  cp "$body_file" "$shift_file"
  shift_id="$(python3 - "$shift_file" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["shift_id"])
PY
)"
  mapfile -t scenario_ids < <(python3 - "$shift_file" <<'PY'
import json, sys
for scenario in json.load(open(sys.argv[1], encoding="utf-8"))["scenarios"]:
    print(scenario["id"])
PY
)
  for scenario_id in "${scenario_ids[@]}"; do
    response_payload="$(python3 - "$scenario_id" "$user_id" <<'PY'
import json, sys
print(json.dumps({
    "scenario_id": sys.argv[1], "verdict": "true_positive", "escalate": False,
    "mitre_ids": [],
    "report_text": "Summary: synthetic. Evidence: synthetic exercise. Actions: reviewed. Unknowns: not yet verified.",
    "time_spent": 1, "user_id": sys.argv[2],
}))
PY
)"
    check_response "shift response ${scenario_id}" POST "/training/shifts/${shift_id}/responses" "$response_payload" 200 shift_response
  done
  check_response "shift completion and summary" POST "/training/shifts/${shift_id}/complete" "$shift_payload" 200 shift_complete
  handover_payload="{\"user_id\":\"${user_id}\",\"note\":\"Synthetic smoke shift complete; follow up with the next analyst.\"}"
  check_response "shift handover coaching" POST "/training/shifts/${shift_id}/handover" "$handover_payload" 200 handover
else
  for label in "shift responses" "shift completion and summary" "shift handover coaching"; do
    echo "FAIL - ${label} (shift start did not succeed)"
    failures=$((failures + 1))
  done
fi

# Invalid/minimal requests verify route, auth and role wiring without invoking
# AI or threat-intelligence providers.
probe_endpoint "correlation API" POST "/api/correlations" '{}' "400 403"
probe_endpoint "incident API" GET "/api/incidents" "" "200 403"
probe_endpoint "threat intel API" POST "/api/threat-intel/lookup" '{}' "400 403"
probe_endpoint "hunting proposal API" POST "/api/hunts/proposals" '{"question":""}' "400 403"
probe_endpoint "admin audit API" GET "/api/admin/audit" "" "200 403"
probe_endpoint "assistant API" POST "/api/assistant/chat" '{}' "400 403"

exit "$failures"
