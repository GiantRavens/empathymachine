#!/usr/bin/env bash
# Install (or uninstall) the empathymachine systemd --user unit.
# Idempotent: re-running just re-syncs the unit file and reloads.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
UNIT_SRC="${SCRIPT_DIR}/empathymachine.service"
UNIT_DEST_DIR="${HOME}/.config/systemd/user"
UNIT_DEST="${UNIT_DEST_DIR}/empathymachine.service"
RELEASE_BIN="${PROJECT_ROOT}/target/release/empathymachine"

usage() {
    cat <<EOF
Usage: install_systemd.sh [--enable] [--no-start] [--uninstall]

  (default)    Copy unit into ${UNIT_DEST_DIR}, daemon-reload, start it
  --enable     Additionally enable autostart on login
  --no-start   Install but don't start (useful before first cert install)
  --uninstall  Stop, disable, and remove the unit
EOF
}

ENABLE=false
START=true
UNINSTALL=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --enable)    ENABLE=true; shift ;;
        --no-start)  START=false; shift ;;
        --uninstall) UNINSTALL=true; shift ;;
        --help|-h)   usage; exit 0 ;;
        *)           echo "unknown flag: $1" >&2; usage >&2; exit 1 ;;
    esac
done

if ! command -v systemctl >/dev/null 2>&1; then
    echo "error: systemctl not found — this script is Linux-only." >&2
    echo "On macOS use scripts/empathymachine.plist + launchctl (see README)." >&2
    exit 1
fi

if [[ "${UNINSTALL}" == true ]]; then
    systemctl --user stop empathymachine.service 2>/dev/null || true
    systemctl --user disable empathymachine.service 2>/dev/null || true
    rm -f "${UNIT_DEST}"
    systemctl --user daemon-reload
    echo "✓ empathymachine.service removed from ${UNIT_DEST_DIR}"
    exit 0
fi

if [[ ! -x "${RELEASE_BIN}" ]]; then
    echo "error: release binary missing at ${RELEASE_BIN}" >&2
    echo "       Build first:  cargo build --release" >&2
    exit 1
fi

mkdir -p "${UNIT_DEST_DIR}"
cp "${UNIT_SRC}" "${UNIT_DEST}"
echo "✓ installed unit → ${UNIT_DEST}"

systemctl --user daemon-reload
echo "✓ systemctl --user daemon-reload"

if [[ "${ENABLE}" == true ]]; then
    systemctl --user enable empathymachine.service
    echo "✓ enabled for autostart on login"
    if command -v loginctl >/dev/null 2>&1; then
        if ! loginctl show-user "${USER}" 2>/dev/null | grep -q "Linger=yes"; then
            echo
            echo "note: to keep the proxy running across logout, run:"
            echo "      sudo loginctl enable-linger ${USER}"
        fi
    fi
fi

if [[ "${START}" == true ]]; then
    systemctl --user restart empathymachine.service
    sleep 1
    systemctl --user --no-pager status empathymachine.service | head -12
fi
