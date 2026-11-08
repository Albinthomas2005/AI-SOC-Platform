#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${REPO_ROOT}/backend/.venv/bin/activate"
export SOC_AI_HOST=127.0.0.1
export SOC_AI_PORT=5000
cd "${REPO_ROOT}/backend"
exec python app.py
