#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

pass() { printf 'PASS - %s\n' "$1"; }
fail() { printf 'FAIL - %s\n' "$1" >&2; exit 1; }

if source backend/.venv/bin/activate && python -m unittest discover backend; then
  pass "backend unit tests"
else
  fail "backend unit tests"
fi

BRANCH="$(git branch --show-current)"
if [[ -n "$BRANCH" ]] && git push -u origin "$BRANCH"; then
  pass "push current branch ($BRANCH)"
else
  fail "push current branch"
fi

CI_OUTPUT="$(./scripts/ci-loop.sh 2>&1)" || {
  printf '%s\n' "$CI_OUTPUT"
  fail "plugin build"
}
printf '%s\n' "$CI_OUTPUT"
RUN_ID="$(printf '%s\n' "$CI_OUTPUT" | sed -nE 's/^Watching run ([0-9]+).*$/\1/p' | tail -n 1)"
[[ -n "$RUN_ID" ]] || fail "plugin build (ci-loop.sh did not print a run ID)"
grep -q 'BUILD PASSED' <<<"$CI_OUTPUT" || fail "plugin build (run $RUN_ID failed)"
pass "plugin build (run $RUN_ID)"

if bash ~/reinstall.sh "$RUN_ID" 2>&1 | tee ~/reinstall.log; then
  grep -q 'INSTALL OK' ~/reinstall.log || fail "plugin reinstall (INSTALL OK missing from ~/reinstall.log)"
  pass "plugin reinstall (run $RUN_ID)"
else
  fail "plugin reinstall (run $RUN_ID)"
fi

if sudo systemctl restart wazuh-dashboard; then
  dashboard_active=0
  for _ in $(seq 1 180); do
    if systemctl is-active --quiet wazuh-dashboard; then
      dashboard_active=1
      break
    fi
    sleep 1
  done
  [[ "$dashboard_active" == 1 ]] || fail "dashboard restart (service did not become active within 180 seconds)"
  pass "dashboard restart"
else
  fail "dashboard restart"
fi

PORT="${SOC_AI_PORT:-5000}"
if [[ ! "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
  fail "backend restart (invalid SOC_AI_PORT)"
fi
if command -v fuser >/dev/null 2>&1; then
  fuser -k "${PORT}/tcp" >/dev/null 2>&1 || true
elif command -v lsof >/dev/null 2>&1; then
  while IFS= read -r pid; do
    [[ -n "$pid" ]] && kill "$pid"
  done < <(lsof -ti "tcp:${PORT}" || true)
else
  fail "backend restart (need fuser or lsof to stop the existing listener)"
fi
nohup ./scripts/run-backend.sh > ~/backend.log 2>&1 < /dev/null &
BACKEND_PID=$!
backend_ready=0
for _ in $(seq 1 60); do
  if curl --silent --show-error --connect-timeout 2 --output /dev/null \
      "http://127.0.0.1:${PORT}/training/scenarios"; then
    backend_ready=1
    break
  fi
  if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    break
  fi
  sleep 1
done
[[ "$backend_ready" == 1 ]] || fail "backend restart (did not listen on port $PORT; see ~/backend.log)"
pass "backend restart (port $PORT)"

if [[ ! -f backend/.env ]]; then
  fail "smoke test (backend/.env is missing)"
fi
set -a
source backend/.env
set +a
export SOC_AI_PORT="$PORT"
[[ -n "${SOC_AI_INTERNAL_TOKEN:-}" ]] || fail "smoke test (SOC_AI_INTERNAL_TOKEN is not set in backend/.env)"
if ./scripts/smoke-test.sh; then
  pass "authenticated smoke test"
else
  fail "authenticated smoke test"
fi

printf '\nAll automated finish steps passed.\n'
printf 'Manual checklist:\n'
printf '  [ ] Browser test\n'
printf '  [ ] Capture 5 screenshots\n'
printf '  [ ] Review answer keys\n'
printf '  [ ] Run live evaluation\n'
