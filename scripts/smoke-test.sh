#!/usr/bin/env bash
set -u

BASE_URL="http://127.0.0.1:5000"

body_file="$(mktemp)"
trap 'rm -f "$body_file"' EXIT
failures=0

check_endpoint() {
  local label="$1" path="$2" check="$3" status
  status="$(curl --silent --show-error --connect-timeout 3 \
    --output "$body_file" --write-out '%{http_code}' \
    --header "Authorization: Bearer ${SOC_AI_INTERNAL_TOKEN:-}" \
    "${BASE_URL}${path}")" || status="000"

  if [[ "$status" == "200" ]] && python3 - "$body_file" "$check" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as source:
        response = json.load(source)
except (OSError, json.JSONDecodeError):
    raise SystemExit(1)

check = sys.argv[2]
progress = response.get("progress") if isinstance(response, dict) else None
valid = response.get("ok") is True
if check == "scenarios":
    valid = valid and isinstance(response.get("scenarios"), list)
elif check == "progress":
    valid = valid and isinstance(progress, dict)
elif check == "export":
    # Markdown export is client-side and consumes these progress arrays.
    valid = (valid and isinstance(progress, dict)
             and isinstance(progress.get("attempts"), list)
             and isinstance(progress.get("unscored_attempts"), list))
raise SystemExit(0 if valid else 1)
PY
  then
    echo "PASS - ${label} (${path})"
  else
    echo "FAIL - ${label} (${path}, HTTP ${status})"
    failures=$((failures + 1))
  fi
}

check_endpoint "scenarios" "/training/scenarios" "scenarios"
check_endpoint "progress" "/training/progress" "progress"
check_endpoint "export data (client-side Markdown source)" "/training/progress" "export"

exit "$failures"
