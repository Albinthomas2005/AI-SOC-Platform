#!/usr/bin/env bash
set -euo pipefail

# Exercises install-plugin.sh --check with isolated fake Dashboard trees and
# command shims. It never reads or writes the host Dashboard installation.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_SCRIPT="$REPO_ROOT/scripts/install-plugin.sh"
TEST_ROOT="$(mktemp -d)"
trap 'chmod -R u+rwx "$TEST_ROOT" 2>/dev/null || true; rm -rf -- "$TEST_ROOT"' EXIT

MOCK_BIN="$TEST_ROOT/mock-bin"
mkdir -p "$MOCK_BIN"
export MOCK_BIN
for tool in bash python3 dirname stat getent cat ls; do
  tool_path="$(command -v "$tool")"
  ln -s "$tool_path" "$MOCK_BIN/$tool"
done

cat > "$MOCK_BIN/sudo" <<'SH'
#!/usr/bin/env bash
set -e
if [[ "${1:-}" == "-v" ]]; then
  exit 0
fi
if [[ "${1:-}" == "test" ]]; then
  shift
  "$MOCK_BIN/test" "$@"
  exit $?
fi
if [[ "${1:-}" == "find" ]]; then
  command "$@"
  exit $?
fi
if [[ "${1:-}" == "sh" ]]; then
  shift
  command sh "$@"
  exit $?
fi
if [[ "${1:-}" == "ls" ]]; then
  shift
  command ls "$@"
  exit $?
fi
echo "unexpected sudo invocation in test: $*" >&2
exit 97
SH

cat > "$MOCK_BIN/test" <<'SH'
#!/usr/bin/env bash
set -e
flag="${1:-}"
path="${2:-}"
case "$flag" in
  -x|-f)
    [[ -n "$FAKE_INSTALLER_PATH" && "$path" == "$FAKE_INSTALLER_PATH" ]] || exit 1
    if [[ "$flag" == "-f" ]]; then
      exit 0
    fi
    [[ "${FAKE_INSTALLER_EXECUTABLE:-0}" == "1" ]]
    ;;
  *)
    echo "unexpected test invocation: $*" >&2
    exit 97
    ;;
esac
SH

cat > "$MOCK_BIN/find" <<'SH'
#!/usr/bin/env bash
set -e
printf '%s' "${FAKE_FIND_RESULT:-}"
[[ -z "${FAKE_FIND_RESULT:-}" ]] || printf '\n'
SH

chmod +x "$MOCK_BIN/sudo" "$MOCK_BIN/test" "$MOCK_BIN/find"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

run_case() {
  local name="$1" installer_name="$2" readable="$3" expected_status="$4"
  local case_root="$TEST_ROOT/$name" dashboard="$TEST_ROOT/$name/dashboard"
  local output status installer="$dashboard/bin/$installer_name"
  local expected_privilege=sudo
  (( EUID == 0 )) && expected_privilege=root
  mkdir -p "$dashboard/bin" "$dashboard/plugins/wazuh"
  cat > "$dashboard/package.json" <<'JSON'
{"name":"opensearch-dashboards","version":"2.19.6"}
JSON
  if [[ "$installer_name" != "-" ]]; then
    printf '#!/bin/sh\nexit 0\n' > "$installer"
    # The normal caller cannot execute this file. The sudo test shim models
    # the Dashboard service owner being able to execute it.
    chmod 000 "$installer"
  else
    installer=""
  fi
  if [[ "$readable" == "yes" ]]; then
    chmod 750 "$dashboard/bin"
  else
    chmod 000 "$dashboard/bin"
  fi
  local find_result=""
  [[ -z "$installer" ]] || find_result="$installer"
  set +e
  output="$(
    PATH="$MOCK_BIN:/usr/bin:/bin" \
    DASHBOARD_HOME="$dashboard" \
    DASHBOARD_OSD_VERSION=2.19.6 \
    DEBUG=1 \
    FAKE_INSTALLER_PATH="$installer" \
    FAKE_INSTALLER_EXECUTABLE="$([[ -n "$installer" ]] && echo 1 || echo 0)" \
    FAKE_FIND_RESULT="$find_result" \
    bash "$INSTALL_SCRIPT" --check 2>&1
  )"
  status=$?
  set -e
  chmod 750 "$dashboard/bin"
  if [[ "$status" -ne "$expected_status" ]]; then
    printf '%s\n' "$output" >&2
    fail "$name returned $status; expected $expected_status"
  fi
  if [[ -n "$installer" ]]; then
    [[ "$output" == *"Self-test passed. Installer: $installer"* ]] || {
      printf '%s\n' "$output" >&2
      fail "$name did not select $installer"
    }
  else
    [[ "$output" == *"Self-test failed: no installer found."* ]] || {
      printf '%s\n' "$output" >&2
      fail "$name did not report missing installer"
    }
  fi
  [[ "$output" == *"command: $expected_privilege test -x"* ]] || {
    printf '%s\n' "$output" >&2
    fail "$name did not check installer executability with privileges"
  }
  printf 'PASS: %s\n' "$name"
}

run_case readable-directory opensearch-dashboards-plugin yes 0
run_case unreadable-directory opensearch-dashboards-plugin no 0
run_case service-owner-only-installer opensearch-dashboards-plugin yes 0
run_case differently-named-installer custom-dashboard-plugin yes 0
run_case no-installer - yes 1

echo 'All installer detection tests passed.'
