#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND="$SCRIPT_DIR/backend"
DATA="$SCRIPT_DIR/data"
mkdir -p "$DATA"

if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 not found. Install Python 3.10+ and retry."
  exit 1
fi

if [ ! -d "$BACKEND/.venv" ]; then
  echo "Creating virtual environment..."
  python3 -m venv "$BACKEND/.venv"
fi

# shellcheck disable=SC1091
source "$BACKEND/.venv/bin/activate"
python3 -m pip install -q --upgrade pip
python3 -m pip install -q -r "$BACKEND/requirements.txt"

PORT="${1:-7070}"
echo
echo "  DarkWebScanner starting at http://localhost:${PORT}"
echo "  Press Ctrl+C to stop."
echo

cd "$SCRIPT_DIR"
exec python3 -m backend.main "$PORT"
