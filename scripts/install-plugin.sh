#!/usr/bin/env bash
set -euo pipefail

# Download and install the Wazuh plugin on a local systemd based installation.
# Optional environment overrides: DASHBOARD_HOME, DASHBOARD_SERVICE,
# DASHBOARD_URL, DASHBOARD_HEALTH_URL. MANUAL_INSTALL=1 explicitly enables
# archive extraction only when no plugin installer executable is available.

WORKFLOW=build-dashboard-plugin.yml
ARTIFACT_NAME=wazuh-plugin-ai-soc
DASHBOARD_HOME="${DASHBOARD_HOME:-/usr/share/wazuh-dashboard}"
DASHBOARD_SERVICE="${DASHBOARD_SERVICE:-wazuh-dashboard}"
DASHBOARD_URL="${DASHBOARD_URL:-https://localhost:5601}"
DASHBOARD_HEALTH_URL="${DASHBOARD_HEALTH_URL:-${DASHBOARD_URL%/}/api/status}"
DASHBOARD_OSD_VERSION="${DASHBOARD_OSD_VERSION:-}"
MANUAL_INSTALL="${MANUAL_INSTALL:-0}"
DEBUG="${DEBUG:-0}"
PLUGIN_ID=wazuh

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_ROOT="$REPO_ROOT/dist"
PLUGIN_CLI="$DASHBOARD_HOME/bin/opensearch-dashboards-plugin"
PLUGIN_ROOT="$DASHBOARD_HOME/plugins"
PLUGIN_DIR="$PLUGIN_ROOT/$PLUGIN_ID"
PLUGIN_BIN_DIR="$DASHBOARD_HOME/bin"
DASHBOARD_PACKAGE="$DASHBOARD_HOME/package.json"
INSTALL_LOG="$DIST_ROOT/install.log"
RUN_ID="${1:-}"
BACKUP_FILE=""
SERVICE_WAS_ACTIVE=0
SERVICE_STOPPED=0
PLUGIN_OWNER=""
PLUGIN_OWNER_UID=""
PLUGIN_OWNER_GID=""
INSTALLER_SOURCE=""
INSTALLER_ARCHIVE_DIR=""

CHECK_ONLY=0
if [[ "${1:-}" == "--check" ]]; then
  CHECK_ONLY=1
  RUN_ID=""
elif [[ $# -gt 1 ]]; then
  echo "Usage: $0 [RUN_ID|--check]" >&2
  exit 2
else
  RUN_ID="${1:-}"
fi

run_privileged() {
  if (( EUID == 0 )); then
    "$@"
  else
    sudo "$@"
  fi
}

run_as_plugin_owner() {
  if [[ "$(id -un)" == "$PLUGIN_OWNER" ]]; then
    "$@"
  else
    sudo -u "$PLUGIN_OWNER" -- "$@"
  fi
}

run_plugin_installer() {
  local action="$1"
  shift
  if [[ "$PLUGIN_OWNER" == "root" ]]; then
    run_as_plugin_owner "$PLUGIN_CLI" "$action" --allow-root "$@"
  else
    run_as_plugin_owner "$PLUGIN_CLI" "$action" "$@"
  fi
}

cleanup_temp() {
  if [[ -n "$INSTALLER_ARCHIVE_DIR" && -d "$INSTALLER_ARCHIVE_DIR" ]]; then
    rm -rf -- "$INSTALLER_ARCHIVE_DIR"
  fi
}
trap cleanup_temp EXIT

is_executable_path() {
  local path="$1"
  local status
  local privilege="sudo"
  (( EUID == 0 )) && privilege="root"
  if [[ "$DEBUG" == "1" ]]; then
    printf 'DEBUG: candidate %s; command: %s test -x %q\n' "$path" "$privilege" "$path" >&2
  fi
  if run_privileged test -x "$path"; then
    status=0
  else
    status=$?
  fi
  if [[ "$DEBUG" == "1" ]]; then
    printf 'DEBUG: candidate %s; command exit=%s\n' "$path" "$status" >&2
  fi
  (( status == 0 )) || return 1

  if [[ "$DEBUG" == "1" ]]; then
    printf 'DEBUG: candidate %s; command: %s test -f %q\n' "$path" "$privilege" "$path" >&2
  fi
  if run_privileged test -f "$path"; then
    status=0
  else
    status=$?
  fi
  if [[ "$DEBUG" == "1" ]]; then
    printf 'DEBUG: candidate %s; command exit=%s\n' "$path" "$status" >&2
  fi
  (( status == 0 ))
}

find_plugin_installer() {
  local candidate=""
  local candidates=""
  local bin_contents

  for candidate in \
    "$PLUGIN_BIN_DIR/opensearch-dashboards-plugin" \
    "$PLUGIN_BIN_DIR/wazuh-dashboard-plugin"; do
    if is_executable_path "$candidate"; then
      PLUGIN_CLI="$candidate"
      INSTALLER_SOURCE="$candidate"
      return 0
    fi
  done

  if [[ "$DEBUG" == "1" ]]; then
    printf "DEBUG: candidate search; command: sudo find %q -maxdepth 1 -type f -name '*plugin*' -print\n" "$PLUGIN_BIN_DIR" >&2
  fi
  if candidates="$(sudo find "$PLUGIN_BIN_DIR" -maxdepth 1 -type f -name '*plugin*' -print 2>/dev/null)"; then
    if [[ "$DEBUG" == "1" ]]; then
      echo 'DEBUG: candidate search; command exit=0' >&2
    fi
  else
    local find_status=$?
    if [[ "$DEBUG" == "1" ]]; then
      printf 'DEBUG: candidate search; command exit=%s\n' "$find_status" >&2
    fi
  fi
  while IFS= read -r candidate; do
    [[ -n "$candidate" ]] || continue
    if is_executable_path "$candidate"; then
      PLUGIN_CLI="$candidate"
      INSTALLER_SOURCE="$candidate"
      return 0
    fi
  done <<< "$candidates"

  local path_lookup_status=0
  if candidate="$(command -v opensearch-dashboards-plugin 2>/dev/null)"; then
    :
  else
    path_lookup_status=$?
    candidate=""
  fi
  if [[ "$DEBUG" == "1" ]]; then
    printf 'DEBUG: candidate PATH:opensearch-dashboards-plugin; command: command -v opensearch-dashboards-plugin; exit=%s\n' "$path_lookup_status" >&2
  fi
  if [[ -z "$candidate" ]] && command -v sudo >/dev/null 2>&1; then
    if candidate="$(sudo sh -c 'command -v opensearch-dashboards-plugin' 2>/dev/null)"; then
      path_lookup_status=0
    else
      path_lookup_status=$?
      candidate=""
    fi
    if [[ "$DEBUG" == "1" ]]; then
      printf 'DEBUG: candidate PATH:opensearch-dashboards-plugin; command: sudo sh -c command -v; exit=%s\n' "$path_lookup_status" >&2
    fi
  fi
  if [[ -n "$candidate" ]] && is_executable_path "$candidate"; then
    PLUGIN_CLI="$candidate"
    INSTALLER_SOURCE="PATH: $candidate"
    return 0
  fi
  echo "No executable plugin installer was found. Contents of $PLUGIN_BIN_DIR:" >&2
  if bin_contents="$(ls -la "$PLUGIN_BIN_DIR" 2>&1)"; then
    printf '%s\n' "$bin_contents" >&2
  elif command -v sudo >/dev/null 2>&1 && bin_contents="$(sudo ls -la "$PLUGIN_BIN_DIR" 2>&1)"; then
    printf '%s\n' "$bin_contents" >&2
  else
    echo "  (directory is missing or could not be listed)" >&2
  fi
  return 1
}

read_owner_ids() {
  local path="$1"
  local ids
  if ids="$(stat -c '%u:%g' "$path" 2>/dev/null)"; then
    printf '%s' "$ids"
  elif command -v sudo >/dev/null 2>&1 && ids="$(sudo stat -c '%u:%g' "$path" 2>/dev/null)"; then
    printf '%s' "$ids"
  else
    return 1
  fi
}

check_dashboard_version() {
  local repo_version content version source candidate candidates output pkg_version
  repo_version="$(python3 - "$REPO_ROOT/wazuh-dashboard/plugins/main/package.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as manifest:
    print(json.load(manifest)["pluginPlatform"]["version"])
PY
)"
  version=""
  source=""
  if content="$(cat "$DASHBOARD_PACKAGE" 2>/dev/null)"; then
    version="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("version", ""))' <<<"$content" 2>/dev/null || true)"
    [[ -n "$version" ]] && source="$DASHBOARD_PACKAGE"
  elif content="$(sudo cat "$DASHBOARD_PACKAGE" 2>/dev/null)"; then
    version="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("version", ""))' <<<"$content" 2>/dev/null || true)"
    [[ -n "$version" ]] && source="$DASHBOARD_PACKAGE (sudo read)"
  fi

  if [[ -z "$version" ]]; then
    candidates="$(sudo find "$DASHBOARD_HOME" -maxdepth 2 -type f -name package.json -print 2>/dev/null || true)"
    while IFS= read -r candidate; do
      [[ -n "$candidate" && "$candidate" != "$DASHBOARD_PACKAGE" ]] || continue
      if content="$(cat "$candidate" 2>/dev/null)"; then
        :
      elif content="$(sudo cat "$candidate" 2>/dev/null)"; then
        :
      else
        continue
      fi
      version="$(python3 -c 'import json,sys; d=json.load(sys.stdin); n=str(d.get("name", "")).lower().replace("_", "-"); print(d.get("version", "") if isinstance(d, dict) and "opensearch-dashboard" in n else "")' <<<"$content" 2>/dev/null || true)"
      if [[ -n "$version" ]]; then
        source="$candidate"
        break
      fi
    done <<< "$candidates"
  fi

  if [[ -z "$version" ]] && sudo test -x "$DASHBOARD_HOME/bin/opensearch-dashboards"; then
    if output="$(run_as_plugin_owner "$DASHBOARD_HOME/bin/opensearch-dashboards" --version 2>&1)"; then
      version="$(python3 -c 'import re,sys; m=re.search(r"(?<![0-9])([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)", sys.stdin.read()); print(m.group(1) if m else "")' <<<"$output")"
      [[ -n "$version" ]] && source="$DASHBOARD_HOME/bin/opensearch-dashboards --version"
    fi
  fi

  if [[ -z "$version" ]]; then
    if command -v dpkg-query >/dev/null 2>&1; then
      pkg_version="$(dpkg-query -W -f='${Version}' wazuh-dashboard 2>/dev/null || true)"
    elif command -v rpm >/dev/null 2>&1; then
      pkg_version="$(rpm -q --qf '%{VERSION}-%{RELEASE}' wazuh-dashboard 2>/dev/null || true)"
    else
      pkg_version=""
    fi
    [[ -n "$pkg_version" ]] && printf 'Wazuh Dashboard package version (not OpenSearch Dashboards): %s\n' "$pkg_version"
    version="$DASHBOARD_OSD_VERSION"
    [[ -n "$version" ]] && source='DASHBOARD_OSD_VERSION (operator supplied)'
  fi

  if [[ -z "$version" ]]; then
    echo 'Cannot determine OpenSearch Dashboards version from package.json, the Dashboard CLI, or DASHBOARD_OSD_VERSION.' >&2
    return 1
  fi
  printf 'Dashboard OpenSearch Dashboards version: %s (source: %s)\nRepository target version: %s\n' "$version" "$source" "$repo_version"
  if [[ "$version" != "$repo_version" ]]; then
    echo "Dashboard version mismatch: found $version, repository requires $repo_version." >&2
    return 1
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
    printf 'Rollback command (stop the service first):\n  sudo systemctl stop %q && sudo rm -rf %q && sudo tar -xzf %q -C %q && sudo systemctl restart %q\n' \
      "$DASHBOARD_SERVICE" "$PLUGIN_DIR" "$BACKUP_FILE" "$PLUGIN_ROOT" "$DASHBOARD_SERVICE"
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

if command -v sudo >/dev/null 2>&1; then
  echo "Checking sudo credentials before inspecting the Dashboard installation."
  if ! sudo -v; then
    echo "Could not validate sudo access; installer detection cannot inspect protected Dashboard files." >&2
    exit 1
  fi
elif (( EUID != 0 )); then
  echo "sudo is required to inspect the protected Dashboard installation." >&2
  exit 1
fi

if (( CHECK_ONLY )); then
  if [[ -d "$PLUGIN_DIR" ]]; then
    OWNER_IDS="$(read_owner_ids "$PLUGIN_DIR")" || {
      echo "Could not determine ownership of $PLUGIN_DIR." >&2
      exit 1
    }
  else
    OWNER_IDS="$(read_owner_ids "$PLUGIN_ROOT")" || {
      echo "Could not determine ownership of $PLUGIN_ROOT." >&2
      exit 1
    }
  fi
  PLUGIN_OWNER_UID="${OWNER_IDS%%:*}"
  PLUGIN_OWNER_GID="${OWNER_IDS##*:}"
  PLUGIN_OWNER_ENTRY="$(getent passwd "$PLUGIN_OWNER_UID" || true)"
  PLUGIN_OWNER="${PLUGIN_OWNER_ENTRY%%:*}"
  if [[ -z "$PLUGIN_OWNER" ]]; then
    echo "Could not map plugin directory owner UID $PLUGIN_OWNER_UID to a user." >&2
    exit 1
  fi
  echo "Plugin directory owner: $PLUGIN_OWNER (UID:GID $PLUGIN_OWNER_UID:$PLUGIN_OWNER_GID)"
  check_dashboard_version || exit 1
  if ! find_plugin_installer; then
    echo 'Self-test failed: no installer found.' >&2
    exit 1
  fi
  printf 'Self-test passed. Installer: %s\nPlugin directory owner: %s\n' "$PLUGIN_CLI" "$PLUGIN_OWNER"
  exit 0
fi

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
read_dashboard_file() {
  local path="$1"
  local contents
  if contents="$(cat "$path" 2>/dev/null)"; then
    printf '%s' "$contents"
    return 0
  fi
  if (( EUID != 0 )) && command -v sudo >/dev/null 2>&1 && contents="$(sudo cat "$path" 2>/dev/null)"; then
    printf '%s' "$contents"
    return 0
  fi
  return 1
}

json_version() {
  python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("version", "") if isinstance(d, dict) else "")' <<<"$1" 2>/dev/null || true
}

json_osd_package_version() {
  python3 -c 'import json,sys; d=json.load(sys.stdin); n=str(d.get("name", "")).lower().replace("_", "-"); print(d.get("version", "") if isinstance(d, dict) and "opensearch-dashboard" in n else "")' <<<"$1" 2>/dev/null || true
}

dashboard_cli_version() {
  local output
  if output="$("$DASHBOARD_HOME/bin/opensearch-dashboards" --version 2>&1)"; then
    :
  elif (( EUID != 0 )) && command -v sudo >/dev/null 2>&1 && output="$(sudo "$DASHBOARD_HOME/bin/opensearch-dashboards" --version 2>&1)"; then
    :
  else
    return 1
  fi
  python3 -c 'import re,sys; m=re.search(r"(?<![0-9])([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)", sys.stdin.read()); print(m.group(1) if m else "")' <<<"$output"
}

DASHBOARD_VERSION=""
DASHBOARD_VERSION_SOURCE=""
WAZUH_PACKAGE_VERSION=""
VERSION_TRIED=()

VERSION_TRIED+=("$DASHBOARD_PACKAGE")
if DASHBOARD_PACKAGE_JSON="$(read_dashboard_file "$DASHBOARD_PACKAGE")"; then
  DASHBOARD_VERSION="$(json_version "$DASHBOARD_PACKAGE_JSON")"
  if [[ -n "$DASHBOARD_VERSION" ]]; then
    DASHBOARD_VERSION_SOURCE="$DASHBOARD_PACKAGE"
  fi
fi

if [[ -z "$DASHBOARD_VERSION" ]]; then
  VERSION_TRIED+=("package.json files within depth 2 named for OpenSearch Dashboards")
  mapfile -t DASHBOARD_PACKAGE_CANDIDATES < <(find "$DASHBOARD_HOME" -maxdepth 2 -type f -name package.json -print 2>/dev/null)
  for package_path in "${DASHBOARD_PACKAGE_CANDIDATES[@]}"; do
    [[ "$package_path" == "$DASHBOARD_PACKAGE" ]] && continue
    if DASHBOARD_PACKAGE_JSON="$(read_dashboard_file "$package_path")"; then
      candidate_version="$(json_osd_package_version "$DASHBOARD_PACKAGE_JSON")"
      if [[ -n "$candidate_version" ]]; then
        DASHBOARD_VERSION="$candidate_version"
        DASHBOARD_VERSION_SOURCE="$package_path"
        break
      fi
    fi
  done
fi

if [[ -z "$DASHBOARD_VERSION" ]]; then
  VERSION_TRIED+=("$DASHBOARD_HOME/bin/opensearch-dashboards --version")
  if [[ -x "$DASHBOARD_HOME/bin/opensearch-dashboards" ]]; then
    DASHBOARD_VERSION="$(dashboard_cli_version || true)"
    if [[ -n "$DASHBOARD_VERSION" ]]; then
      DASHBOARD_VERSION_SOURCE="$DASHBOARD_HOME/bin/opensearch-dashboards --version"
    fi
  fi
fi

if [[ -z "$DASHBOARD_VERSION" ]]; then
  VERSION_TRIED+=("dpkg-query or rpm -q wazuh-dashboard (Wazuh package version only)")
  if command -v dpkg-query >/dev/null 2>&1; then
    WAZUH_PACKAGE_VERSION="$(dpkg-query -W -f='${Version}' wazuh-dashboard 2>/dev/null || true)"
  elif command -v rpm >/dev/null 2>&1; then
    WAZUH_PACKAGE_VERSION="$(rpm -q --qf '%{VERSION}-%{RELEASE}' wazuh-dashboard 2>/dev/null || true)"
  fi
  if [[ -n "$WAZUH_PACKAGE_VERSION" ]]; then
    printf 'Wazuh Dashboard package version (not the OpenSearch Dashboards version): %s\n' "$WAZUH_PACKAGE_VERSION"
  fi
  if [[ -n "$DASHBOARD_OSD_VERSION" ]]; then
    DASHBOARD_VERSION="$DASHBOARD_OSD_VERSION"
    DASHBOARD_VERSION_SOURCE='DASHBOARD_OSD_VERSION environment variable (operator supplied)'
  fi
fi

if [[ -z "$DASHBOARD_VERSION" ]]; then
  printf 'Cannot determine the OpenSearch Dashboards version. Tried:\n' >&2
  printf '  - %s\n' "${VERSION_TRIED[@]}" >&2
  echo 'If the version is known, rerun with DASHBOARD_OSD_VERSION=<version> (for example 2.19.6).' >&2
  exit 1
fi

printf 'Dashboard OpenSearch Dashboards version: %s (source: %s)\nPlugin required OpenSearch Dashboards version: %s\nRepository target version: %s\n' \
  "$DASHBOARD_VERSION" "$DASHBOARD_VERSION_SOURCE" "$ZIP_OSD_VERSION" "$REPO_OSD_VERSION"
if [[ -z "$DASHBOARD_VERSION" || "$ZIP_OSD_VERSION" != "$DASHBOARD_VERSION" ]]; then
  echo "WARNING: plugin requires OpenSearch Dashboards $ZIP_OSD_VERSION but the installed Dashboard is $DASHBOARD_VERSION; refusing to install." >&2
  exit 1
fi
if [[ "$DASHBOARD_VERSION" != "$REPO_OSD_VERSION" ]]; then
  echo "WARNING: installed Dashboard version $DASHBOARD_VERSION does not match this repository's target $REPO_OSD_VERSION; refusing to install." >&2
  exit 1
fi

if find_plugin_installer; then
  MANUAL_MODE=0
  echo "Plugin installer found: $INSTALLER_SOURCE"
else
  if [[ "$MANUAL_INSTALL" == "1" ]]; then
    MANUAL_MODE=1
    echo "MANUAL_INSTALL=1: using the explicit manual extraction fallback."
  else
    echo "To use the documented manual extraction fallback, rerun with MANUAL_INSTALL=1." >&2
    exit 1
  fi
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

if [[ -d "$PLUGIN_DIR" ]]; then
  OWNER_IDS="$(read_owner_ids "$PLUGIN_DIR")" || {
    echo "Could not determine ownership of $PLUGIN_DIR." >&2
    exit 1
  }
else
  OWNER_IDS="$(read_owner_ids "$PLUGIN_ROOT")" || {
    echo "Could not determine ownership of $PLUGIN_ROOT." >&2
    exit 1
  }
fi
PLUGIN_OWNER_UID="${OWNER_IDS%%:*}"
PLUGIN_OWNER_GID="${OWNER_IDS##*:}"
PLUGIN_OWNER_ENTRY="$(getent passwd "$PLUGIN_OWNER_UID" || true)"
PLUGIN_OWNER="${PLUGIN_OWNER_ENTRY%%:*}"
if [[ -z "$PLUGIN_OWNER" ]]; then
  echo "Could not map plugin directory owner UID $PLUGIN_OWNER_UID to a user." >&2
  exit 1
fi
if [[ "$PLUGIN_OWNER" != "root" && "$(id -un)" != "$PLUGIN_OWNER" ]] && ! command -v sudo >/dev/null 2>&1; then
  echo "sudo is required to run the plugin installer as $PLUGIN_OWNER." >&2
  exit 1
fi
echo "Plugin directory owner: $PLUGIN_OWNER (UID:GID $PLUGIN_OWNER_UID:$PLUGIN_OWNER_GID)"

if NODE_RUNTIME_OUTPUT="$(run_as_plugin_owner "$DASHBOARD_HOME/bin/opensearch-dashboards" --version 2>&1)"; then
  printf 'Dashboard Node runtime works as %s: %s\n' "$PLUGIN_OWNER" "$NODE_RUNTIME_OUTPUT"
else
  printf 'Dashboard Node runtime check failed as %s. The wrapper could not run its bundled Node runtime.\n%s\n' \
    "$PLUGIN_OWNER" "$NODE_RUNTIME_OUTPUT" >&2
  exit 1
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

if (( MANUAL_MODE )); then
  MANUAL_EXTRACT_DIR="$(mktemp -d "$ARTIFACT_DIR/manual-extract.XXXXXX")"
  if unzip -q "$PLUGIN_ZIP" -d "$MANUAL_EXTRACT_DIR" >>"$INSTALL_LOG" 2>&1; then
    :
  else
    install_status=$?
    on_error "$install_status"
  fi
  MANIFEST_RELATIVE="${MANIFEST_ENTRY%/*}"
  if [[ "$MANIFEST_RELATIVE" == "$MANIFEST_ENTRY" ]]; then
    MANUAL_SOURCE_DIR="$MANUAL_EXTRACT_DIR"
  else
    MANUAL_SOURCE_DIR="$MANUAL_EXTRACT_DIR/$MANIFEST_RELATIVE"
  fi
  if [[ ! -d "$MANUAL_SOURCE_DIR" || ! -f "$MANUAL_SOURCE_DIR/opensearch_dashboards.json" ]]; then
    echo "Manual extraction did not produce a plugin folder containing opensearch_dashboards.json." >&2
    exit 1
  fi
  MANUAL_MANIFEST_ID="$(python3 - "$MANUAL_SOURCE_DIR/opensearch_dashboards.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as manifest:
    print(json.load(manifest).get("id", ""))
PY
)"
  if [[ "$MANUAL_MANIFEST_ID" != "$PLUGIN_ID" ]]; then
    echo "Manual extraction contains plugin '$MANUAL_MANIFEST_ID', expected '$PLUGIN_ID'; refusing to install." >&2
    exit 1
  fi

  MANUAL_STAGE_DIR="$(run_privileged mktemp -d "$PLUGIN_ROOT/.${PLUGIN_ID}-install.XXXXXX")"
  if run_privileged cp -a "$MANUAL_SOURCE_DIR/." "$MANUAL_STAGE_DIR/" >>"$INSTALL_LOG" 2>&1 && \
    run_privileged chown -R "$PLUGIN_OWNER_UID:$PLUGIN_OWNER_GID" "$MANUAL_STAGE_DIR" >>"$INSTALL_LOG" 2>&1; then
    :
  else
    install_status=$?
    on_error "$install_status"
  fi
  if [[ -e "$PLUGIN_DIR" || -L "$PLUGIN_DIR" ]]; then
    if [[ ! -f "$BACKUP_FILE" ]]; then
      echo "Refusing to remove $PLUGIN_DIR because no backup exists for run $RUN_ID." >&2
      exit 1
    fi
    if run_privileged rm -rf "$PLUGIN_DIR" >>"$INSTALL_LOG" 2>&1; then
      :
    else
      install_status=$?
      on_error "$install_status"
    fi
  fi
  if run_privileged mv "$MANUAL_STAGE_DIR" "$PLUGIN_DIR" >>"$INSTALL_LOG" 2>&1; then
    :
  else
    install_status=$?
    on_error "$install_status"
  fi
  echo "Plugin installed manually at $PLUGIN_DIR with owner $PLUGIN_OWNER_UID:$PLUGIN_OWNER_GID."
else
  if [[ -e "$PLUGIN_DIR" || -L "$PLUGIN_DIR" ]]; then
    if [[ ! -f "$BACKUP_FILE" ]]; then
      echo "Refusing to remove $PLUGIN_DIR because no backup exists for run $RUN_ID." >&2
      exit 1
    fi
    if run_plugin_installer remove "$PLUGIN_ID" >>"$INSTALL_LOG" 2>&1; then
      :
    else
      install_status=$?
      on_error "$install_status"
    fi
  fi
  INSTALLER_ARCHIVE_DIR="$(mktemp -d /tmp/wazuh-plugin-archive.XXXXXX)"
  INSTALLER_ARCHIVE="$INSTALLER_ARCHIVE_DIR/$(basename "$PLUGIN_ZIP")"
  cp "$PLUGIN_ZIP" "$INSTALLER_ARCHIVE"
  chmod 0755 "$INSTALLER_ARCHIVE_DIR"
  chmod 0644 "$INSTALLER_ARCHIVE"
  PLUGIN_FILE_URI="$(python3 - "$INSTALLER_ARCHIVE" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).resolve().as_uri())
PY
)"
  if run_plugin_installer install "$PLUGIN_FILE_URI" --batch >>"$INSTALL_LOG" 2>&1; then
    :
  else
    install_status=$?
    on_error "$install_status"
  fi
  rm -rf "$INSTALLER_ARCHIVE_DIR"
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
