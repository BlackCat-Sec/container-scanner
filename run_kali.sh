#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${VENV_DIR:-$SCRIPT_DIR/.venv}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
STAMP_FILE="$VENV_DIR/.requirements.sha256"
REQ_FILE="$SCRIPT_DIR/requirements.txt"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "python3 was not found. Install it first: sudo apt install -y python3 python3-venv" >&2
  exit 1
fi

if ! command -v sha256sum >/dev/null 2>&1; then
  echo "sha256sum was not found. Install coreutils first." >&2
  exit 1
fi

if [ ! -x "$VENV_DIR/bin/python" ]; then
  if ! "$PYTHON_BIN" -m venv "$VENV_DIR"; then
    echo "Failed to create a virtual environment." >&2
    echo "On Kali, install the missing pieces with:" >&2
    echo "  sudo apt install -y python3-venv python3-pip" >&2
    exit 1
  fi

  if ! "$VENV_DIR/bin/python" -m pip install --upgrade pip; then
    echo "Failed to bootstrap pip inside the virtual environment." >&2
    exit 1
  fi
fi

REQ_HASH="$(sha256sum "$REQ_FILE" | awk '{print $1}')"
CURRENT_HASH=""
if [ -f "$STAMP_FILE" ]; then
  CURRENT_HASH="$(cat "$STAMP_FILE")"
fi

if [ "$REQ_HASH" != "$CURRENT_HASH" ]; then
  if ! "$VENV_DIR/bin/python" -m pip install -r "$REQ_FILE"; then
    echo "Dependency installation failed." >&2
    echo "Check your network access, then rerun: bash run_kali.sh --help" >&2
    exit 1
  fi
  printf '%s' "$REQ_HASH" > "$STAMP_FILE"
fi

exec "$VENV_DIR/bin/python" "$SCRIPT_DIR/main.py" "$@"
