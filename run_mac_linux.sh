#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND="$SCRIPT_DIR/backend"
DATA="$SCRIPT_DIR/data"
mkdir -p "$DATA"

# ── upstream repo for the in-app updater ─────────────────────────────────────
# By default the updater fetches from the same GitHub repo this code came from.
# If you've set up a public mirror repo (see .github/workflows/mirror-to-public.yml),
# uncomment and adjust to make operator hosts pull from the public channel —
# no GitHub token required on the host.
# export DWS_UPSTREAM_OWNER="enfierno21"
# export DWS_UPSTREAM_REPO="DarkWebScanner-Public"
# export DWS_UPSTREAM_BRANCH="main"

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
echo "  On first run, watch for the admin token URL printed below."
echo "  The token is also saved to: $DATA/admin_token.txt"
echo "  Press Ctrl+C to stop."
echo

cd "$SCRIPT_DIR"
exec python3 -m backend.main "$PORT"
