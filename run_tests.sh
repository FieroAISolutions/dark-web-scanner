#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND="$SCRIPT_DIR/backend"

if [ ! -d "$BACKEND/.venv" ]; then
  echo "Creating virtual environment..."
  python3 -m venv "$BACKEND/.venv"
fi

# shellcheck disable=SC1091
source "$BACKEND/.venv/bin/activate"
python3 -m pip install -q --upgrade pip
python3 -m pip install -q -r "$BACKEND/requirements-dev.txt"

cd "$SCRIPT_DIR"
exec python3 -m pytest "$@"
