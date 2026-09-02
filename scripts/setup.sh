#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPOSITORY_ROOT"

if [[ -n "${PYTHON_COMMAND:-}" ]]; then
  PYTHON_EXECUTABLE="$PYTHON_COMMAND"
elif command -v python3.11 >/dev/null 2>&1; then
  PYTHON_EXECUTABLE="python3.11"
else
  PYTHON_EXECUTABLE="python3"
fi

if ! command -v "$PYTHON_EXECUTABLE" >/dev/null 2>&1; then
  echo "Python 3.11+ is required. See docs/setup.md." >&2
  exit 1
fi

"$PYTHON_EXECUTABLE" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else "Python 3.11+ is required")'
"$PYTHON_EXECUTABLE" -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt

if ! command -v npm >/dev/null 2>&1; then
  echo "Node.js and npm are required for the frontend. See docs/setup.md." >&2
  exit 1
fi

npm --prefix frontend ci

echo "Setup complete. Activate Python with: source .venv/bin/activate"
echo "Then verify TShark with: python scripts/check_tshark.py"
