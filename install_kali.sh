#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="${HOME}/.local/bin"
TARGET_FILE="${TARGET_DIR}/container-scanner"
BOOTSTRAP=1

for arg in "$@"; do
  case "$arg" in
    --skip-bootstrap) BOOTSTRAP=0 ;;
    *)
      echo "Usage: bash install_kali.sh [--skip-bootstrap]" >&2
      exit 1
      ;;
  esac
done

mkdir -p "$TARGET_DIR"

cat > "$TARGET_FILE" <<EOF
#!/usr/bin/env bash
set -euo pipefail
exec bash "$SCRIPT_DIR/run_kali.sh" "\$@"
EOF

chmod +x "$TARGET_FILE"

if [ "$BOOTSTRAP" -eq 1 ]; then
  if ! "$TARGET_FILE" --help >/dev/null; then
    echo "The wrapper was installed, but bootstrap verification failed." >&2
    echo "Run '${TARGET_FILE} --help' manually after fixing the environment." >&2
    exit 1
  fi
fi

echo "Installed ${TARGET_FILE}"
echo "Run '${TARGET_FILE} --help' to confirm the command is available."
