#!/usr/bin/env bash

set -u

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
backend_dir=$(cd -- "$script_dir/.." && pwd)
env_file="$backend_dir/.env"
port=${1:-5000}
base_url="http://127.0.0.1:${port}"

if ! [[ "$port" =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then
  printf '%s\n' 'FAIL: port must be an integer between 1 and 65535.'
  exit 2
fi

if [[ ! -r "$env_file" ]]; then
  printf '%s\n' 'FAIL: backend/.env is missing or unreadable.'
  exit 2
fi

token=$(grep -m 1 '^SOC_AI_INTERNAL_TOKEN=' "$env_file" | cut -d= -f2-)
tmp_dir=$(mktemp -d) || {
  printf '%s\n' 'FAIL: could not create temporary files.'
  exit 2
}
trap 'rm -f "$tmp_dir/unauthenticated.json" "$tmp_dir/authenticated.json" "$tmp_dir/request.json"; rmdir "$tmp_dir"' EXIT

python3 - "$backend_dir/synthetic_alert.json" "$tmp_dir/request.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    alert = json.load(source)
with open(sys.argv[2], "w", encoding="utf-8") as target:
    json.dump({"alert": alert}, target)
PY

failed=0
if status=$(curl -sS -o "$tmp_dir/unauthenticated.json" -w '%{http_code}' \
  -X POST "$base_url/api/ai/analyze-alert" \
  -H 'Content-Type: application/json' \
  --data-binary "@$tmp_dir/request.json"); then
  if [[ "$status" == 401 ]]; then
    printf '%s\n' 'PASS: request without token returned 401.'
  else
    printf 'FAIL: request without token returned HTTP %s (expected 401).\n' "$status"
    failed=1
  fi
else
  printf '%s\n' 'FAIL: request without token could not reach the backend.'
  failed=1
fi

if [[ -z "$token" ]]; then
  printf '%s\n' 'FAIL: SOC_AI_INTERNAL_TOKEN is missing from backend/.env.'
  failed=1
elif status=$(curl -sS -o "$tmp_dir/authenticated.json" -w '%{http_code}' \
  -X POST "$base_url/api/ai/analyze-alert" \
  -H "Authorization: Bearer $token" \
  -H 'Content-Type: application/json' \
  --data-binary "@$tmp_dir/request.json"); then
  if [[ "$status" == 200 ]] && python3 - "$tmp_dir/authenticated.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as response:
    result = json.load(response)
sys.exit(0 if result.get("ok") is True else 1)
PY
  then
    printf '%s\n' 'PASS: authenticated synthetic alert returned ok=true.'
  else
    printf 'FAIL: authenticated request returned HTTP %s or ok was not true.\n' "$status"
    failed=1
  fi
else
  printf '%s\n' 'FAIL: authenticated request could not reach the backend.'
  failed=1
fi

unset token
exit "$failed"
