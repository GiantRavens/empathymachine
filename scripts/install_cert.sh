#!/usr/bin/env bash
# Install (or uninstall) EmpathyMachine's root CA into the OS trust store
# and any Firefox profile NSS databases found.
#
# Linux:  /usr/local/share/ca-certificates/empathymachine.crt + update-ca-certificates
# macOS:  security add-trusted-cert ... /Library/Keychains/System.keychain
# Firefox: certutil -A -d sql:<profile> -n "<NICK>" -t "C,," -i <pem>
#
# This sidesteps the "Keychain Access → File → Import → Always Trust" dance
# documented in the README. macOS still prompts for your password (sudo).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PEM_SRC="${PROJECT_ROOT}/certs/root_ca.pem"
NICKNAME="EmpathyMachine"

UNINSTALL=false
SKIP_FIREFOX=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --uninstall)   UNINSTALL=true; shift ;;
        --no-firefox)  SKIP_FIREFOX=true; shift ;;
        --help|-h)
            cat <<EOF
Usage: install_cert.sh [--uninstall] [--no-firefox]

Default action: trust ${PEM_SRC} in the OS trust store + every detected
Firefox profile. --uninstall reverses both.
EOF
            exit 0 ;;
        *) echo "unknown flag: $1" >&2; exit 1 ;;
    esac
done

if [[ ! -f "${PEM_SRC}" && "${UNINSTALL}" == false ]]; then
    echo "error: no CA at ${PEM_SRC} — run './empathymachine start' once to generate it" >&2
    exit 1
fi

OS="$(uname -s)"

# ─── OS trust store ──────────────────────────────────────────────────────

install_os_linux() {
    local dest="/usr/local/share/ca-certificates/empathymachine.crt"
    echo "→ Linux trust store: ${dest} (sudo)"
    sudo cp "${PEM_SRC}" "${dest}"
    sudo update-ca-certificates >/dev/null
    echo "  ✓ trusted"
}

uninstall_os_linux() {
    local dest="/usr/local/share/ca-certificates/empathymachine.crt"
    if [[ -f "${dest}" ]]; then
        echo "→ Linux trust store: removing ${dest} (sudo)"
        sudo rm -f "${dest}"
        sudo update-ca-certificates --fresh >/dev/null 2>&1 || sudo update-ca-certificates >/dev/null
        echo "  ✓ removed"
    else
        echo "→ Linux trust store: nothing installed"
    fi
}

install_os_macos() {
    echo "→ macOS System keychain (will prompt for password)"
    sudo security add-trusted-cert -d -r trustRoot \
        -k /Library/Keychains/System.keychain "${PEM_SRC}"
    echo "  ✓ trusted"
}

uninstall_os_macos() {
    local sha
    sha=$(openssl x509 -in "${PEM_SRC}" -noout -fingerprint -sha1 2>/dev/null \
          | sed 's/^.*=//' | tr -d ':' || true)
    if [[ -n "${sha}" ]]; then
        echo "→ macOS System keychain: removing by fingerprint (will prompt)"
        sudo security delete-certificate -Z "${sha}" \
            /Library/Keychains/System.keychain 2>/dev/null \
            || echo "  (no matching cert; may already be removed)"
    else
        echo "→ macOS uninstall skipped: source pem missing, can't compute fingerprint"
    fi
}

# ─── Firefox NSS databases ───────────────────────────────────────────────

find_firefox_profiles() {
    # Echo each profile dir that contains a cert*.db. Searches Linux + macOS paths.
    local roots=(
        "${HOME}/.mozilla/firefox"
        "${HOME}/snap/firefox/common/.mozilla/firefox"
        "${HOME}/.var/app/org.mozilla.firefox/.mozilla/firefox"
        "${HOME}/Library/Application Support/Firefox/Profiles"
    )
    for root in "${roots[@]}"; do
        [[ -d "${root}" ]] || continue
        # Profile dirs have a cert9.db (sqlite) or older cert8.db
        find "${root}" -maxdepth 2 -type f \( -name cert9.db -o -name cert8.db \) \
            -printf '%h\n' 2>/dev/null | sort -u
    done
}

install_firefox() {
    if ! command -v certutil >/dev/null 2>&1; then
        echo "→ Firefox: certutil not found — skipping"
        echo "  install with: sudo apt install libnss3-tools  (Debian/Ubuntu)"
        echo "                brew install nss                 (macOS)"
        return 0
    fi
    local found=0
    while IFS= read -r profile; do
        [[ -z "${profile}" ]] && continue
        found=1
        local dbdir="sql:${profile}"
        # Idempotent: delete-then-add
        certutil -D -n "${NICKNAME}" -d "${dbdir}" 2>/dev/null || true
        if certutil -A -n "${NICKNAME}" -t "C,," -i "${PEM_SRC}" -d "${dbdir}" 2>/dev/null; then
            echo "→ Firefox profile: ${profile}  ✓ trusted"
        else
            echo "→ Firefox profile: ${profile}  ✗ certutil failed"
        fi
    done < <(find_firefox_profiles)
    if [[ "${found}" == 0 ]]; then
        echo "→ Firefox: no profiles found"
    fi
}

uninstall_firefox() {
    if ! command -v certutil >/dev/null 2>&1; then
        echo "→ Firefox: certutil not found — skipping"
        return 0
    fi
    while IFS= read -r profile; do
        [[ -z "${profile}" ]] && continue
        if certutil -D -n "${NICKNAME}" -d "sql:${profile}" 2>/dev/null; then
            echo "→ Firefox profile: ${profile}  ✓ removed"
        fi
    done < <(find_firefox_profiles)
}

# ─── dispatch ────────────────────────────────────────────────────────────

if [[ "${UNINSTALL}" == true ]]; then
    case "${OS}" in
        Linux)  uninstall_os_linux ;;
        Darwin) uninstall_os_macos ;;
        *)      echo "unsupported OS: ${OS}" >&2; exit 1 ;;
    esac
    [[ "${SKIP_FIREFOX}" == false ]] && uninstall_firefox
    echo
    echo "Note: Chrome/Edge on Linux use the system trust store (done)."
    echo "      Chrome/Safari on macOS use the System keychain (done)."
    echo "      Restart browsers to pick up the change."
    exit 0
fi

case "${OS}" in
    Linux)  install_os_linux ;;
    Darwin) install_os_macos ;;
    *)      echo "unsupported OS: ${OS}" >&2; exit 1 ;;
esac
[[ "${SKIP_FIREFOX}" == false ]] && install_firefox

echo
echo "Done. Restart your browsers to pick up the new trusted root."
echo "Verify with:  curl --cacert ${PEM_SRC} https://www.google.com -o /dev/null -sS -w '%{http_code}\\n'"
