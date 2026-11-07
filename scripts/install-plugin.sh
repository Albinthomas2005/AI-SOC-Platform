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
DASHBOARD_PACKAGE="$DASHBOARD_HOME/package.json"
INSTALL_LOG="$DIST_ROOT/install.log"
RUN_ID="${1:-}"
BACKUP_FILE=""
SERVICE_WAS_ACTIVE=0
SERVICE_STOPPED=0

run_privileged() {
  if (( EUID == 0 )); then
    "$@"
  else
    sudo "$@"
  fi
}

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

print_rollback_command() {
  if [[ -n "$BACKUP_FILE" && -f "$BACKUP_FILE" ]]; then
    printf 'Rollback command (stop the service first):\n  sudo systemctl stop %q && sudo %q remove %q && sudo tar -xzf %q -C %q && sudo systemctl restart %q\n' \
      "$DASHBOARD_SERVICE" "$PLUGIN_CLI" "$PLUGIN_ID" "$BACKUP_FILE" "$PLUGIN_ROOT" "$DASHBOARD_SERVICE"
  else
    echo "No prior plugin backup exists, so there is no previous plugin version to restore."
  fi
}

on_error() {
  local status="${1:-$?}"
  trap - ERR
  echo "Plugin installation failed (exit $status)." >&2
  if [[ -s "$INSTALL_LOG" ]]; then
    echo "Last 40 installer log lines ($INSTALL_LOG):" >&2
    tail -n 40 "$INSTALL_LOG" >&2 || true
  fi
  print_rollback_command >&2
  if (( SERVICE_STOPPED && SERVICE_WAS_ACTIVE )); then
    echo "Attempting to bring the previously running Dashboard service back up." >&2
    run_privileged systemctl start "$DASHBOARD_SERVICE" || true
  fi
  print_log_commands >&2
  exit "$status"
}
trap 'on_error $?' ERR

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
ZIP_LIST="$ARTIFACT_DIR/zip-files.txt"
find "$ARTIFACT_DIR" -type f -name '*.zip' -print > "$ZIP_LIST"
mapfile -t ZIP_FILES < "$ZIP_LIST"
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
ZIP_LISTING="$ARTIFACT_DIR/zip-contents.txt"
unzip -Z1 "$PLUGIN_ZIP" > "$ZIP_LISTING"
MANIFEST_ENTRY=""
while IFS= read -r entry; do
  if [[ -z "$MANIFEST_ENTRY" && ( "$entry" == "opensearch_dashboards.json" || "$entry" == */opensearch_dashboards.json ) ]]; then
    MANIFEST_ENTRY="$entry"
  fi
done < "$ZIP_LISTING"
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
if [[ ! -f "$DASHBOARD_PACKAGE" ]]; then
  echo "Cannot read Dashboard version: $DASHBOARD_PACKAGE is missing." >&2
  exit 1
fi
if [[ -r "$DASHBOARD_PACKAGE" ]]; then
  DASHBOARD_PACKAGE_JSON="$(cat "$DASHBOARD_PACKAGE")"
elif (( EUID != 0 )) && command -v sudo >/dev/null 2>&1; then
  echo "Using sudo to read the system-managed Dashboard package metadata."
  DASHBOARD_PACKAGE_JSON="$(sudo cat "$DASHBOARD_PACKAGE")"
else
  echo "Cannot read Dashboard package metadata at $DASHBOARD_PACKAGE." >&2
  exit 1
fi
DASHBOARD_VERSION="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("version", ""))' <<<"$DASHBOARD_PACKAGE_JSON")"
printf 'Dashboard version: %s\nPlugin required version: %s\nRepository target: %s\n' \
  "$DASHBOARD_VERSION" "$ZIP_OSD_VERSION" "$REPO_OSD_VERSION"
if [[ -z "$DASHBOARD_VERSION" || "$ZIP_OSD_VERSION" != "$DASHBOARD_VERSION" ]]; then
  echo "WARNING: plugin requires OpenSearch Dashboards $ZIP_OSD_VERSION but the installed Dashboard is $DASHBOARD_VERSION; refusing to install." >&2
  exit 1
fi
if [[ "$DASHBOARD_VERSION" != "$REPO_OSD_VERSION" ]]; then
  echo "WARNING: installed Dashboard version $DASHBOARD_VERSION does not match this repository's target $REPO_OSD_VERSION; refusing to install." >&2
  exit 1
fi

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

BACKUP_DIR="$DIST_ROOT/backups"
BACKUP_FILE="$BACKUP_DIR/wazuh-plugin-${RUN_ID}.tar.gz"
if [[ -f "$BACKUP_FILE" ]]; then
  run_privileged tar -tzf "$BACKUP_FILE" >/dev/null
  echo "Reusing existing backup for run $RUN_ID: $BACKUP_FILE"
  print_rollback_command
elif [[ -e "$PLUGIN_DIR" || -L "$PLUGIN_DIR" ]]; then
  mkdir -p "$BACKUP_DIR"
  run_privileged tar -C "$PLUGIN_ROOT" -czf "$BACKUP_FILE" "$PLUGIN_ID"
  echo "Existing plugin backup created: $BACKUP_FILE"
  print_rollback_command
else
  echo "No existing $PLUGIN_ID plugin directory found; installing without removal."
fi

: > "$INSTALL_LOG"
if systemctl is-active --quiet "$DASHBOARD_SERVICE"; then
  SERVICE_WAS_ACTIVE=1
  run_privileged systemctl stop "$DASHBOARD_SERVICE"
  SERVICE_STOPPED=1
fi

if [[ -e "$PLUGIN_DIR" || -L "$PLUGIN_DIR" ]]; then
  if [[ ! -f "$BACKUP_FILE" ]]; then
    echo "Refusing to remove $PLUGIN_DIR because no backup exists for run $RUN_ID." >&2
    exit 1
  fi
  if run_privileged "$PLUGIN_CLI" remove "$PLUGIN_ID" >>"$INSTALL_LOG" 2>&1; then
    :
  else
    install_status=$?
    on_error "$install_status"
  fi
fi
PLUGIN_FILE_URI="$(python3 - "$PLUGIN_ZIP" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).resolve().as_uri())
PY
)"
if run_privileged "$PLUGIN_CLI" install --batch "$PLUGIN_FILE_URI" >>"$INSTALL_LOG" 2>&1; then
  :
else
  install_status=$?
  on_error "$install_status"
fi
run_privileged systemctl restart "$DASHBOARD_SERVICE"
SERVICE_STOPPED=0
trap - ERR

echo "Waiting up to 120 seconds for $DASHBOARD_HEALTH_URL"
DEADLINE=$((SECONDS + 120))
until curl -kfsS --connect-timeout 2 --max-time 5 "$DASHBOARD_HEALTH_URL" -o /dev/null; do
  if (( SECONDS >= DEADLINE )); then
    echo "Dashboard health check failed after 120 seconds." >&2
    if [[ -s "$INSTALL_LOG" ]]; then
      echo "Last 40 installer log lines ($INSTALL_LOG):" >&2
      tail -n 40 "$INSTALL_LOG" >&2 || true
    fi
    print_rollback_command >&2
    print_log_commands >&2
    exit 1
  fi
  sleep 5
done
echo "Dashboard health check passed."
