#!/usr/bin/env bash
# Install (or uninstall) the empathymachine launchd LaunchAgent on macOS.
# User-level (no sudo): plist lives at ~/Library/LaunchAgents/.
# Idempotent — re-running re-syncs the plist and reloads.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LABEL="com.giantravens.empathymachine"
NETWATCH_LABEL="com.giantravens.empathymachine-netwatch"
TEMPLATE="${SCRIPT_DIR}/${LABEL}.plist"
NETWATCH_TEMPLATE="${SCRIPT_DIR}/${NETWATCH_LABEL}.plist"
DEST_DIR="${HOME}/Library/LaunchAgents"
DEST="${DEST_DIR}/${LABEL}.plist"
NETWATCH_DEST="${DEST_DIR}/${NETWATCH_LABEL}.plist"
RELEASE_BIN="${PROJECT_ROOT}/target/release/empathymachine"

usage() {
    cat <<EOF
Usage: install_launchd.sh [--enable] [--no-start] [--uninstall]

  (default)    Install plist into ${DEST_DIR}, load + start
  --enable     No-op for compat with install_systemd.sh (launchd autostarts via RunAtLoad)
  --no-start   Install plist but don't load it yet
  --uninstall  Unload and remove the plist
EOF
}

START=true
UNINSTALL=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --enable)    shift ;;
        --no-start)  START=false; shift ;;
        --uninstall) UNINSTALL=true; shift ;;
        --help|-h)   usage; exit 0 ;;
        *)           echo "unknown flag: $1" >&2; usage >&2; exit 1 ;;
    esac
done

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "error: launchd is macOS-only. Use scripts/install_systemd.sh on Linux." >&2
    exit 1
fi

if [[ "${UNINSTALL}" == true ]]; then
    for plist in "${DEST}" "${NETWATCH_DEST}"; do
        if [[ -f "${plist}" ]]; then
            launchctl unload "${plist}" 2>/dev/null || true
            rm -f "${plist}"
            echo "✓ removed ${plist}"
        else
            echo "no plist at ${plist}"
        fi
    done
    exit 0
fi

if [[ ! -x "${RELEASE_BIN}" ]]; then
    echo "error: release binary missing at ${RELEASE_BIN}" >&2
    echo "       Build first:  cargo build --release" >&2
    exit 1
fi

if [[ ! -f "${TEMPLATE}" ]]; then
    echo "error: plist template missing at ${TEMPLATE}" >&2
    exit 1
fi

# Ad-hoc code-sign the release binary so Little Snitch (and other identity-
# based firewalls) see a stable signature hash and stop prompting per-
# destination. Without this, LS refuses to apply broad "any process" rules
# to unsigned binaries — every new outbound destination triggers a fresh
# alert. `--sign -` is the ad-hoc identity (self-signed, no Apple Developer
# ID needed); `--force` overwrites any prior signature.
if command -v codesign >/dev/null 2>&1; then
    if codesign --sign - --force "${RELEASE_BIN}" 2>/dev/null; then
        # Extract CDHash for the confirmation line. -dvvv puts it on stderr.
        cdhash=$(codesign -dvvv "${RELEASE_BIN}" 2>&1 | awk -F= '/^CDHash=/ {print $2; exit}')
        echo "✓ ad-hoc signed binary (CDHash: ${cdhash:-<unknown>})"
    else
        echo "  (codesign skipped — non-fatal; LS will prompt per-destination)"
    fi
fi

mkdir -p "${DEST_DIR}"
mkdir -p "${HOME}/Library/Logs"

# Install the standalone proxy-reapply script to ~/.empathymachine/
# (TCC-accessible from LaunchAgents; ~/Desktop is not).
mkdir -p "${HOME}/.empathymachine"
if [[ -f "${SCRIPT_DIR}/em-proxy-reapply" ]]; then
    cp "${SCRIPT_DIR}/em-proxy-reapply" "${HOME}/.empathymachine/em-proxy-reapply"
    chmod +x "${HOME}/.empathymachine/em-proxy-reapply"
    # Strip any quarantine xattr that might have come from Syncthing/scp.
    xattr -c "${HOME}/.empathymachine/em-proxy-reapply" 2>/dev/null || true
    echo "✓ installed em-proxy-reapply → ${HOME}/.empathymachine/em-proxy-reapply"
fi

# Substitute paths into both templates (sed -i differs across BSD/GNU; do it via redirect).
sed -e "s|__PROJECT_ROOT__|${PROJECT_ROOT}|g" \
    -e "s|__HOME__|${HOME}|g" \
    "${TEMPLATE}" > "${DEST}"
echo "✓ installed plist → ${DEST}"

if [[ -f "${NETWATCH_TEMPLATE}" ]]; then
    sed -e "s|__PROJECT_ROOT__|${PROJECT_ROOT}|g" \
        -e "s|__HOME__|${HOME}|g" \
        "${NETWATCH_TEMPLATE}" > "${NETWATCH_DEST}"
    echo "✓ installed netwatch plist → ${NETWATCH_DEST}"
fi

# Reload (unload-then-load) so plist changes take effect.
for plist in "${DEST}" "${NETWATCH_DEST}"; do
    [[ -f "${plist}" ]] && launchctl unload "${plist}" 2>/dev/null || true
done

if [[ "${START}" == true ]]; then
    for plist in "${DEST}" "${NETWATCH_DEST}"; do
        if [[ -f "${plist}" ]]; then
            launchctl load -w "${plist}"
        fi
    done
    echo "✓ launchctl load -w (both agents enabled for autostart on login)"
    sleep 1
    if launchctl list | grep -q "${LABEL}"; then
        local_pid=$(launchctl list "${LABEL}" 2>/dev/null \
                    | awk -F'"' '/"PID"/ {print $2}' \
                    | awk -F'=' '{print $2}' | tr -d ' ;')
        echo "✓ ${LABEL} is loaded (pid=${local_pid:-?})"
        echo
        echo "logs:           ~/Library/Logs/empathymachine.log"
        echo "netwatch logs:  ~/Library/Logs/empathymachine-netwatch.log"
        echo "status:         ./empathymachine status"
        echo "stop:           ./empathymachine stop"
    else
        echo "✗ ${LABEL} not in launchctl list after load"
        echo "  check ~/Library/Logs/empathymachine.log for errors"
        exit 1
    fi
fi
