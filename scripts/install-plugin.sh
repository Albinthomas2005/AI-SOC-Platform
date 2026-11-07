#!/usr/bin/env bash
set -euo pipefail

# Download and install the Wazuh plugin on a local systemd based installation.
# Optional environment overrides: DASHBOARD_HOME, DASHBOARD_SERVICE,
# DASHBOARD_URL, DASHBOARD_HEALTH_URL.

WORKFLOW=build-dashboard-plugin.yml
ARTIFACT_NAME=wazuh-plugin-ai-soc
DASHBOARD_HOME="${DASHBOARD_HOME:-/usr/share/wazuh-dashboard}"
DASHBOARD_SERVICE="${DASHBOARD_SERVICE:-wazuh-dashboard}"
DASHBOARD_URL="${DASHBOARD_URL:-https://localhost:5601}"
DASHBOARD_HEALTH_URL="${DASHBOARD_HEALTH_URL:-${DASHBOARD_URL%/}/api/status}"
PLUGIN_ID=wazuh

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_ROOT="$REPO_ROOT/dist"
PLUGIN_CLI="$DASHBOARD_HOME/bin/opensearch-dashboards-plugin"
PLUGIN_ROOT="$DASHBOARD_HOME/plugins"
PLUGIN_DIR="$PLUGIN_ROOT/$PLUGIN_ID"
RUN_ID="${1:-}"

print_log_commands() {
  echo "Dashboard diagnostics to check:"
  if (( EUID == 0 )); then
    echo "  journalctl -u '$DASHBOARD_SERVICE' -n 100 --no-pager"
    echo "  tail -n 100 /var/log/wazuh-dashboard/wazuh-dashboard.log"
  else
    echo "  sudo journalctl -u '$DASHBOARD_SERVICE' -n 100 --no-pager"
    echo "  sudo tail -n 100 /var/log/wazuh-dashboard/wazuh-dashboard.log"
  fi
}

SERVICE_WAS_ACTIVE=0
SERVICE_STOPPED=0
on_error() {
  local status=$?
  trap - ERR
  echo "Plugin installation failed (exit $status)." >&2
  if (( SERVICE_STOPPED && SERVICE_WAS_ACTIVE )); then
    echo "Attempting to bring the previously running Dashboard service back up." >&2
    if (( EUID == 0 )); then
      systemctl start "$DASHBOARD_SERVICE" || true
    else
      sudo systemctl start "$DASHBOARD_SERVICE" || true
    fi
  fi
  print_log_commands >&2
  exit "$status"
}
trap on_error ERR

if [[ $# -gt 1 ]]; then
  echo "Usage: $0 [RUN_ID]" >&2
  exit 2
fi

if [[ -z "$RUN_ID" ]]; then
  RUN_ID="$(gh run list --workflow="$WORKFLOW" --status=success --limit=1 --json databaseId -q '.[0].databaseId')"
fi
if [[ ! "$RUN_ID" =~ ^[0-9]+$ ]]; then
  echo "Could not determine a successful workflow run ID." >&2
  exit 1
fi

mkdir -p "$DIST_ROOT"
ARTIFACT_DIR="$(mktemp -d "$DIST_ROOT/run-${RUN_ID}.XXXXXX")"
gh run download "$RUN_ID" --name "$ARTIFACT_NAME" --dir "$ARTIFACT_DIR"
mapfile -t ZIP_FILES < <(find "$ARTIFACT_DIR" -type f -name '*.zip' -print)
if [[ ${#ZIP_FILES[@]} -ne 1 ]]; then
  echo "Expected exactly one plugin ZIP in artifact '$ARTIFACT_NAME'; found ${#ZIP_FILES[@]}." >&2
  exit 1
fi
PLUGIN_ZIP="${ZIP_FILES[0]}"
unzip -t "$PLUGIN_ZIP" >/dev/null
printf 'Plugin archive: %s\n' "$(basename "$PLUGIN_ZIP")"
printf 'SHA-256: '
sha256sum "$PLUGIN_ZIP"

REPO_OSD_VERSION="$(python3 - "$REPO_ROOT/wazuh-dashboard/plugins/main/package.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as manifest:
    print(json.load(manifest)["pluginPlatform"]["version"])
PY
)"
MANIFEST_ENTRY="$(unzip -Z1 "$PLUGIN_ZIP" | awk '$0 == "opensearch_dashboards.json" || /\/opensearch_dashboards.json$/ { print; exit }')"
if [[ -z "$MANIFEST_ENTRY" ]]; then
  echo "WARNING: plugin ZIP has no opensearch_dashboards.json; refusing to install because its required Dashboard version cannot be checked." >&2
  exit 1
fi
ZIP_MANIFEST="$(unzip -p "$PLUGIN_ZIP" "$MANIFEST_ENTRY")"
ZIP_PLUGIN_ID="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("id", ""))' <<<"$ZIP_MANIFEST")"
ZIP_OSD_VERSION="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("opensearchDashboardsVersion", ""))' <<<"$ZIP_MANIFEST")"
if [[ "$ZIP_PLUGIN_ID" != "$PLUGIN_ID" ]]; then
  echo "WARNING: expected plugin '$PLUGIN_ID' but ZIP manifest identifies '$ZIP_PLUGIN_ID'; refusing to install." >&2
  exit 1
fi
if [[ -z "$ZIP_OSD_VERSION" || "$ZIP_OSD_VERSION" == "opensearchDashboards" ]]; then
  echo "WARNING: plugin ZIP does not contain a resolved OpenSearch Dashboards version; refusing to install." >&2
  exit 1
fi
if [[ "$ZIP_OSD_VERSION" != "$REPO_OSD_VERSION" ]]; then
  echo "WARNING: plugin requires OpenSearch Dashboards $ZIP_OSD_VERSION but this repository targets $REPO_OSD_VERSION; refusing to install." >&2
  exit 1
fi
printf 'Version check: plugin requires OpenSearch Dashboards %s; repository target is %s (match).\n' "$ZIP_OSD_VERSION" "$REPO_OSD_VERSION"

if [[ ! -x "$PLUGIN_CLI" ]]; then
  echo "Plugin installer not found at $PLUGIN_CLI. Set DASHBOARD_HOME to the local Wazuh Dashboard installation." >&2
  exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl is unavailable; this script expects the repository's documented host systemd installation." >&2
  exit 1
fi
if (( EUID != 0 )); then
  if ! command -v sudo >/dev/null 2>&1; then
    echo "The system install under $DASHBOARD_HOME requires root privileges; run as root or install sudo." >&2
    exit 1
  fi
  echo "Using sudo because $DASHBOARD_HOME and the wazuh-dashboard systemd unit are system-managed."
fi

run_privileged() {
  if (( EUID == 0 )); then
    "$@"
  else
    sudo "$@"
  fi
}

BACKUP_FILE=""
if [[ -d "$PLUGIN_DIR" ]]; then
  BACKUP_DIR="$DIST_ROOT/backups"
  mkdir -p "$BACKUP_DIR"
  BACKUP_FILE="$BACKUP_DIR/wazuh-plugin-${RUN_ID}-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
  run_privileged tar -C "$PLUGIN_ROOT" -czf "$BACKUP_FILE" "$PLUGIN_ID"
  echo "Existing plugin backup: $BACKUP_FILE"
  printf 'Rollback command (after stopping the service):\n  sudo %q remove %q && sudo tar -xzf %q -C %q && sudo systemctl restart %q\n' \
    "$PLUGIN_CLI" "$PLUGIN_ID" "$BACKUP_FILE" "$PLUGIN_ROOT" "$DASHBOARD_SERVICE"
else
  echo "No existing $PLUGIN_ID plugin directory found; installing without removal."
fi

if systemctl is-active --quiet "$DASHBOARD_SERVICE"; then
  SERVICE_WAS_ACTIVE=1
  run_privileged systemctl stop "$DASHBOARD_SERVICE"
  SERVICE_STOPPED=1
fi

if [[ -d "$PLUGIN_DIR" ]]; then
  run_privileged "$PLUGIN_CLI" remove "$PLUGIN_ID"
fi
PLUGIN_FILE_URI="$(python3 - "$PLUGIN_ZIP" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).resolve().as_uri())
PY
)"
run_privileged "$PLUGIN_CLI" install "$PLUGIN_FILE_URI"
run_privileged systemctl restart "$DASHBOARD_SERVICE"
SERVICE_STOPPED=0
trap - ERR

echo "Waiting up to 120 seconds for $DASHBOARD_HEALTH_URL"
DEADLINE=$((SECONDS + 120))
until curl -kfsS --connect-timeout 2 --max-time 5 "$DASHBOARD_HEALTH_URL" -o /dev/null; do
  if (( SECONDS >= DEADLINE )); then
    echo "Dashboard health check failed after 120 seconds." >&2
    print_log_commands >&2
    exit 1
  fi
  sleep 5
done
echo "Dashboard health check passed."
