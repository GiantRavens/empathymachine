#!/usr/bin/env bash
# Install (or uninstall) the EmpathyMachine menu-bar/tray app.
#
#   macOS: copies tray.py to ~/.empathymachine/, creates a Python venv there,
#          installs pystray+Pillow, registers a LaunchAgent for autostart.
#   Linux: copies tray.py to ~/.empathymachine/, creates a venv, writes a
#          .desktop autostart entry to ~/.config/autostart/. Requires
#          gnome-shell-extension-appindicator on pure GNOME (preinstalled on
#          Pop_OS!/Cinnamon/Pantheon; install via apt on stock GNOME).
#
# Idempotent — re-run to update tray.py from source or re-install plist.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
EM_HOME="${HOME}/.empathymachine"
TRAY_SRC="${PROJECT_ROOT}/gui/tray.py"
REQS_SRC="${PROJECT_ROOT}/gui/requirements.txt"
PLIST_TEMPLATE="${SCRIPT_DIR}/com.giantravens.empathymachine-tray.plist"
PLIST_DEST="${HOME}/Library/LaunchAgents/com.giantravens.empathymachine-tray.plist"
DESKTOP_AUTOSTART="${HOME}/.config/autostart/empathymachine-tray.desktop"
LABEL="com.giantravens.empathymachine-tray"

usage() {
    cat <<EOF
Usage: install_tray.sh [--no-start] [--uninstall]

  (default)    Install tray.py + venv to ~/.empathymachine/, register autostart, launch
  --no-start   Install but don't launch (still registers autostart for next login)
  --uninstall  Stop and remove tray + autostart
EOF
}

START=true
UNINSTALL=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-start)  START=false; shift ;;
        --uninstall) UNINSTALL=true; shift ;;
        --help|-h)   usage; exit 0 ;;
        *)           echo "unknown flag: $1" >&2; usage >&2; exit 1 ;;
    esac
done

OS="$(uname -s)"

# ─── uninstall ───────────────────────────────────────────────────────────

if [[ "${UNINSTALL}" == true ]]; then
    if [[ "${OS}" == "Darwin" ]]; then
        if [[ -f "${PLIST_DEST}" ]]; then
            launchctl unload "${PLIST_DEST}" 2>/dev/null || true
            rm -f "${PLIST_DEST}"
            echo "✓ removed ${PLIST_DEST}"
        fi
        # Best-effort kill if still running outside launchd
        pkill -f "${EM_HOME}/tray.py" 2>/dev/null || true
    elif [[ "${OS}" == "Linux" ]]; then
        if [[ -f "${DESKTOP_AUTOSTART}" ]]; then
            rm -f "${DESKTOP_AUTOSTART}"
            echo "✓ removed ${DESKTOP_AUTOSTART}"
        fi
        pkill -f "${EM_HOME}/tray.py" 2>/dev/null || true
    fi
    echo
    echo "Tray autostart removed. Files at ${EM_HOME}/ are left for re-install."
    echo "To wipe entirely:  rm -rf ${EM_HOME}/.venv ${EM_HOME}/tray.py"
    exit 0
fi

# ─── prereqs ─────────────────────────────────────────────────────────────

if [[ ! -f "${TRAY_SRC}" ]]; then
    echo "error: tray.py missing at ${TRAY_SRC}" >&2
    exit 1
fi

if ! command -v uv >/dev/null 2>&1; then
    if [[ -x /opt/homebrew/bin/uv ]]; then
        export PATH="/opt/homebrew/bin:${PATH}"
    elif [[ -x "${HOME}/.local/bin/uv" ]]; then
        export PATH="${HOME}/.local/bin:${PATH}"
    else
        echo "error: uv not found (install via 'curl -LsSf https://astral.sh/uv/install.sh | sh' or brew install uv)" >&2
        exit 1
    fi
fi

# ─── install files ──────────────────────────────────────────────────────

mkdir -p "${EM_HOME}"

# Copy tray.py + strip any quarantine xattr (Mac).
cp "${TRAY_SRC}" "${EM_HOME}/tray.py"
chmod +x "${EM_HOME}/tray.py"
[[ "${OS}" == "Darwin" ]] && xattr -c "${EM_HOME}/tray.py" 2>/dev/null || true
echo "✓ installed tray.py → ${EM_HOME}/tray.py"

# Create venv at ~/.empathymachine/.venv if missing.
VENV="${EM_HOME}/.venv"
if [[ ! -x "${VENV}/bin/python" ]]; then
    echo "→ creating venv at ${VENV}"
    uv venv "${VENV}" --python python3
fi

# Install/update deps. --native-tls on Mac so it trusts the EmpathyMachine
# MITM CA when the user has system proxy ON during install.
echo "→ installing tray dependencies"
if [[ "${OS}" == "Darwin" ]]; then
    uv pip install --native-tls --python "${VENV}/bin/python" -r "${REQS_SRC}" 2>&1 | tail -3
else
    uv pip install --python "${VENV}/bin/python" -r "${REQS_SRC}" 2>&1 | tail -3
fi
echo "✓ deps installed in ${VENV}"

# ─── autostart wiring ────────────────────────────────────────────────────

if [[ "${OS}" == "Darwin" ]]; then
    mkdir -p "${HOME}/Library/Logs"
    sed -e "s|__HOME__|${HOME}|g" "${PLIST_TEMPLATE}" > "${PLIST_DEST}"
    echo "✓ installed LaunchAgent → ${PLIST_DEST}"
    # Reload
    launchctl unload "${PLIST_DEST}" 2>/dev/null || true
    if [[ "${START}" == true ]]; then
        launchctl load -w "${PLIST_DEST}"
        echo "✓ launchctl load -w (autostart at login enabled)"
    fi
elif [[ "${OS}" == "Linux" ]]; then
    mkdir -p "${HOME}/.config/autostart"
    cat > "${DESKTOP_AUTOSTART}" <<EOF
[Desktop Entry]
Type=Application
Name=EmpathyMachine Tray
Comment=Menu-bar control for the EmpathyMachine inspecting proxy
Exec=${VENV}/bin/python ${EM_HOME}/tray.py
Icon=network-vpn
Terminal=false
X-GNOME-Autostart-enabled=true
EOF
    echo "✓ installed autostart → ${DESKTOP_AUTOSTART}"
    if [[ "${START}" == true ]]; then
        # Start in background (detach from this shell).
        nohup "${VENV}/bin/python" "${EM_HOME}/tray.py" \
            >> "${EM_HOME}/tray.log" 2>&1 &
        disown
        echo "✓ tray launched (pid $!)"
        echo "  log: ${EM_HOME}/tray.log"
    fi
fi

echo
echo "Done. Check the menu bar (Mac) / system tray (Linux GNOME/KDE)."
if [[ "${OS}" == "Linux" ]]; then
    echo "If you don't see the icon on pure GNOME:"
    echo "  sudo apt install gnome-shell-extension-appindicator"
    echo "  (then enable via Extensions app + log out/in)"
fi
