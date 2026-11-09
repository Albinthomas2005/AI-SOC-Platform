#!/usr/bin/env bash
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SAMPLE="$REPO_ROOT/backend/lab_samples/ssh_bruteforce.log"
BACKEND_URL="${SOC_AI_BASE_URL:-http://${SOC_AI_HOST:-127.0.0.1}:${SOC_AI_PORT:-5000}}"
BACKEND_URL="${BACKEND_URL%/}"
TARGET_LOG="${SOC_AI_INJECT_PATH:-/var/log/soc-ai-lab.log}"
ALERTS_FILE="${WAZUH_ALERTS_FILE:-/var/ossec/logs/alerts/alerts.json}"
DASHBOARD_URL="${DASHBOARD_URL:-}"
DASHBOARD_COOKIE="${DASHBOARD_COOKIE:-}"

while (($#)); do
  case "$1" in
    --dashboard-url) DASHBOARD_URL="${2:-}"; shift 2 ;;
    --cookie) DASHBOARD_COOKIE="${2:-}"; shift 2 ;;
    *) echo "Usage: $0 [--dashboard-url URL] [--cookie COOKIE]" >&2; exit 2 ;;
  esac
done

temp_dir="$(mktemp -d)"
trap 'rm -rf "$temp_dir"' EXIT
chmod 700 "$temp_dir"
payload_file="$temp_dir/upload.json"
headers_file="$temp_dir/headers"
response_file="$temp_dir/response"
response_headers="$temp_dir/response-headers"
tail_file="$temp_dir/tail"
failed_stages=()

print_response() {
  local response_path="$1"
  UPLOAD_DIAG_TOKEN="$token" python3 - "$response_path" "$SAMPLE" <<'PY'
import json
import os
import sys

response_path, sample_path = sys.argv[1:]
try:
    text = open(response_path, encoding="utf-8", errors="replace").read()
except OSError:
    print("<response body unavailable>")
    raise SystemExit
token = os.environ.get("UPLOAD_DIAG_TOKEN", "")
try:
    sample = open(sample_path, encoding="utf-8").read()
except OSError:
    sample = ""
if token:
    text = text.replace(token, "[redacted]")
if sample:
    text = text.replace(sample, "[file content redacted]")
    for line in sample.splitlines():
        if line:
            text = text.replace(line, "[file line redacted]")
try:
    body = json.loads(text)
except json.JSONDecodeError:
    print(text[:4096] if text else "<empty body>")
else:
    def sanitize(value, key=""):
        if isinstance(value, dict):
            return {k: ("[redacted]" if k.lower() in {"content", "full_log", "log"} else sanitize(v, k)) for k, v in value.items()}
        if isinstance(value, list):
            return [sanitize(item, key) for item in value]
        if isinstance(value, str):
            value = value.replace(token, "[redacted]") if token else value
            if sample:
                value = value.replace(sample, "[file content redacted]")
                for line in sample.splitlines():
                    if line:
                        value = value.replace(line, "[file line redacted]")
            return value
        return value
    print(json.dumps(sanitize(body), ensure_ascii=False))
PY
}

echo "STAGE flask-health endpoint=backend/api/lab/samples"
health_status="$(curl --silent --show-error --connect-timeout 3 --max-time 5 \
  --output "$response_file" --write-out '%{http_code}' \
  "$BACKEND_URL/api/lab/samples" 2>/dev/null)" || health_status=000
if [[ "$health_status" == 000 ]]; then
  echo "FAILED_STAGE=flask-health status=000"
  failed_stages+=(flask-health)
else
  echo "STAGE flask-health status=$health_status reachable=yes"
fi

python3 - "$SAMPLE" "$payload_file" <<'PY'
import json
import sys
from pathlib import Path

sample = Path(sys.argv[1])
Path(sys.argv[2]).write_text(json.dumps({
    "filename": sample.name,
    "content": sample.read_text(encoding="utf-8"),
    "title": "SSH upload diagnostic",
    "platform": "linux",
}), encoding="utf-8")
PY
chmod 600 "$payload_file"

token="${SOC_AI_INTERNAL_TOKEN:-}"
if [[ -z "$token" && -r "$REPO_ROOT/backend/.env" ]]; then
  token="$(python3 - "$REPO_ROOT/backend/.env" <<'PY'
import sys

try:
    lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
except OSError:
    lines = []
for line in lines:
    line = line.strip()
    if line.startswith("export "):
        line = line[7:].lstrip()
    if line.startswith("SOC_AI_INTERNAL_TOKEN="):
        value = line.split("=", 1)[1].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        print(value)
        break
PY
)"
fi

direct_status=000
if [[ -z "$token" ]]; then
  echo "FAILED_STAGE=flask-upload reason=backend_token_not_available"
  failed_stages+=(flask-upload)
else
  printf '%s\n' 'Content-Type: application/json' "Authorization: Bearer $token" 'X-SOC-User: upload-diagnostic' > "$headers_file"
  chmod 600 "$headers_file"
  echo "STAGE flask-upload endpoint=backend/api/lab/uploads sample_lines=$(wc -l < "$SAMPLE" | tr -d ' ')"
  direct_status="$(curl --silent --show-error --connect-timeout 3 --max-time 55 \
    --header "@$headers_file" --data-binary "@$payload_file" \
    --output "$response_file" --write-out '%{http_code}' \
    "$BACKEND_URL/api/lab/uploads" 2>/dev/null)" || direct_status=000
  echo "STAGE flask-upload status=$direct_status response_body:"
  print_response "$response_file"
  if [[ "$direct_status" != 201 ]]; then failed_stages+=(flask-upload); fi
fi

echo "STAGE target-log path=$TARGET_LOG"
if [[ -r "$TARGET_LOG" ]]; then
  tail -n 4 "$TARGET_LOG" > "$tail_file"
  echo "target-log tail_lines=$(wc -l < "$tail_file" | tr -d ' ') (contents withheld)"
else
  echo "target-log unavailable_or_unreadable=yes"
fi

echo "STAGE alerts-by-location path=$ALERTS_FILE target=$TARGET_LOG"
python3 - "$ALERTS_FILE" "$TARGET_LOG" <<'PY'
import json
import sys
from datetime import datetime
from pathlib import Path

alerts_path, target = Path(sys.argv[1]), Path(sys.argv[2])
try:
    with alerts_path.open("rb") as source:
        source.seek(0, 2)
        size = source.tell()
        source.seek(max(0, size - 4 * 1024 * 1024))
        text = source.read().decode("utf-8", errors="replace")
except OSError:
    print("alerts status=unavailable")
    raise SystemExit
lines = text.splitlines()
if size > 4 * 1024 * 1024 and lines:
    lines = lines[1:]
target_path = str(target.resolve())
matches = []
for line in lines:
    try:
        alert = json.loads(line)
        location = alert.get("location")
        if isinstance(location, str) and str(Path(location).resolve()) == target_path:
            matches.append(alert.get("timestamp", "unknown"))
    except (json.JSONDecodeError, OSError, TypeError):
        continue
print(f"alerts matching_location={len(matches)} newest_timestamp={matches[-1] if matches else 'none'}")
PY

if [[ -n "$DASHBOARD_URL" || -n "$DASHBOARD_COOKIE" ]]; then
  DASHBOARD_URL="${DASHBOARD_URL:-http://127.0.0.1:5601}"
  DASHBOARD_URL="${DASHBOARD_URL%/}"
  : > "$headers_file"
  printf '%s\n' 'Content-Type: application/json' 'osd-xsrf: true' > "$headers_file"
  [[ -n "$DASHBOARD_COOKIE" ]] && printf 'Cookie: %s\n' "$DASHBOARD_COOKIE" >> "$headers_file"
  chmod 600 "$headers_file"
  echo "STAGE dashboard-proxy endpoint=dashboard/api/phase/lab/uploads sample_lines=$(wc -l < "$SAMPLE" | tr -d ' ')"
  proxy_status="$(curl --silent --show-error --connect-timeout 3 --max-time 55 \
    --header "@$headers_file" --data-binary "@$payload_file" \
    --dump-header "$response_headers" --output "$response_file" --write-out '%{http_code}' \
    "$DASHBOARD_URL/api/phase/lab/uploads" 2>/dev/null)" || proxy_status=000
  build_version="$(awk 'tolower($1)=="x-soc-ai-build:" {gsub("\r", "", $2); print $2}' "$response_headers" 2>/dev/null | tail -n 1)"
  echo "STAGE dashboard-proxy status=$proxy_status build=${build_version:-missing} response_body:"
  print_response "$response_file"
  if [[ "$proxy_status" != 201 ]]; then failed_stages+=(dashboard-proxy); fi
fi

if ((${#failed_stages[@]})); then
  printf 'FAILED_STAGE=%s\n' "$(IFS=,; echo "${failed_stages[*]}")"
  exit 1
fi
echo 'FAILED_STAGE=none'
