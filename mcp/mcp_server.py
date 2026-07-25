#!/usr/bin/env python3
"""EmpathyMachine MCP Server.

Makes the proxy LLM-addressable. Read tools shell to the admin HTTP API
at 127.0.0.1:8081; write tools edit blocklists/custom.txt or config.yaml
and bounce the service so the change takes effect.

Until the Rust binary grows a SIGHUP reload (graduation: empathymachine
PLAN.md), write tools rely on a process restart. Restart is ~1 s with
systemd and the release binary.

Usage (stdio transport for Claude Code / Claude Desktop):
    /path/to/empathymachine/.venv-mcp/bin/python mcp/mcp_server.py
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import urllib.request
from pathlib import Path

from mcp.server.fastmcp import FastMCP


# ─── paths ───────────────────────────────────────────────────────────────

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
_CUSTOM_BLOCKLIST = _ROOT / "blocklists" / "custom.txt"
_LAUNCHER = _ROOT / "empathymachine"
_ADMIN_URL = "http://127.0.0.1:8081"
_SERVICE = "empathymachine.service"

# ─── helpers ─────────────────────────────────────────────────────────────

_DOMAIN_RE = re.compile(
    r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)


def _validate_domain(domain: str) -> str:
    """Normalize + validate a hostname (also accepts leading '*.'). Raise on invalid."""
    d = domain.strip().lower()
    if not d:
        raise ValueError("empty domain")
    if not _DOMAIN_RE.match(d):
        raise ValueError(f"not a valid hostname: {domain!r}")
    return d


def _fetch_json(path: str, timeout: float = 2.0) -> dict:
    url = f"{_ADMIN_URL}{path}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception as e:
        return {"error": f"admin API unreachable at {url}: {type(e).__name__}: {e}"}


def _systemd_available() -> bool:
    if not shutil.which("systemctl"):
        return False
    r = subprocess.run(
        ["systemctl", "--user", "list-unit-files"],
        capture_output=True, text=True,
    )
    return _SERVICE in r.stdout


def _restart_proxy() -> dict:
    """Restart via systemd if installed; otherwise via the launcher."""
    if _systemd_available():
        r = subprocess.run(
            ["systemctl", "--user", "restart", _SERVICE],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            return {"status": "restarted", "via": "systemd"}
        return {"status": "error", "via": "systemd",
                "stderr": (r.stderr or "").strip()[:400]}
    r = subprocess.run(
        [str(_LAUNCHER), "restart"], capture_output=True, text=True,
    )
    return {"status": "restarted" if r.returncode == 0 else "error",
            "via": "launcher",
            "stdout": (r.stdout or "").strip()[:200],
            "stderr": (r.stderr or "").strip()[:400]}


def _read_custom_blocks() -> list[str]:
    if not _CUSTOM_BLOCKLIST.exists():
        return []
    out = []
    for ln in _CUSTOM_BLOCKLIST.read_text().splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        # hosts-format lines look like "0.0.0.0 domain" or just "domain"
        parts = s.split()
        candidate = parts[-1] if parts else ""
        if candidate:
            out.append(candidate.lower())
    return out


def _write_custom_blocks(domains: list[str], *, header_note: str = "") -> None:
    _CUSTOM_BLOCKLIST.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# blocklists/custom.txt — managed by EmpathyMachine MCP",
        "# Add/remove via the MCP server; manual edits are preserved across rewrites",
        "# Hosts-format: one domain per line; '0.0.0.0' prefix optional",
    ]
    if header_note:
        lines.append(f"# {header_note}")
    lines.append("")
    seen = set()
    for d in domains:
        if d in seen:
            continue
        seen.add(d)
        lines.append(f"0.0.0.0 {d}")
    _CUSTOM_BLOCKLIST.write_text("\n".join(lines) + "\n")


# ─── server ──────────────────────────────────────────────────────────────

mcp = FastMCP("empathymachine")


@mcp.tool()
def status() -> dict:
    """Report whether the proxy is running, its uptime, listen addresses,
    and the most recent admin API readings. Combines systemd state with
    a live /api/status fetch.
    """
    out: dict = {}
    if _systemd_available():
        r = subprocess.run(
            ["systemctl", "--user", "is-active", _SERVICE],
            capture_output=True, text=True,
        )
        out["systemd_state"] = r.stdout.strip() or "unknown"
    else:
        out["systemd_state"] = "unit-not-installed"
    out["admin_status"] = _fetch_json("/api/status")
    return out


@mcp.tool()
def metrics() -> dict:
    """Return request/block/error counters and latency stats from the proxy."""
    return _fetch_json("/api/metrics")


@mcp.tool()
def recent_blocks(limit: int = 20) -> dict:
    """Return the most recent blocked requests with their reason and matched rule.

    `limit` caps the number of entries (server may return fewer).
    """
    data = _fetch_json("/api/blocked/recent")
    if isinstance(data, dict) and "error" in data:
        return data
    # Admin API returns {"events": [...]} (verified against current handler);
    # fall back to common alternatives so future schema tweaks don't break us.
    items = None
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        for k in ("events", "items", "recent", "blocked"):
            if isinstance(data.get(k), list):
                items = data[k]
                break
    if items is None:
        return {"raw": data}
    return {"count": min(len(items), limit), "items": items[:limit]}


@mcp.tool()
def list_custom_blocks() -> dict:
    """Return every domain in blocklists/custom.txt (the manually-curated list)."""
    domains = _read_custom_blocks()
    return {"count": len(domains), "domains": domains,
            "path": str(_CUSTOM_BLOCKLIST)}


@mcp.tool()
def add_block(domain: str, restart: bool = True) -> dict:
    """Block a domain by appending it to blocklists/custom.txt.

    Set `restart=False` to defer the proxy bounce (useful when batching).
    The change takes effect only after the proxy reloads its blocklists.
    """
    try:
        d = _validate_domain(domain)
    except ValueError as e:
        return {"status": "invalid", "error": str(e)}
    current = _read_custom_blocks()
    if d in current:
        return {"status": "already_blocked", "domain": d}
    current.append(d)
    _write_custom_blocks(current, header_note=f"last MCP edit: add {d}")
    # Count from the on-disk file so the reported total reflects post-dedup
    # state (existing custom.txt files may contain duplicates).
    result = {"status": "added", "domain": d, "total_custom": len(_read_custom_blocks())}
    if restart:
        result["restart"] = _restart_proxy()
    return result


@mcp.tool()
def remove_block(domain: str, restart: bool = True) -> dict:
    """Stop blocking a domain (removes it from blocklists/custom.txt).

    Does not touch subscribed remote lists — those domains will continue
    to be blocked until removed upstream.
    """
    try:
        d = _validate_domain(domain)
    except ValueError as e:
        return {"status": "invalid", "error": str(e)}
    current = _read_custom_blocks()
    if d not in current:
        return {"status": "not_present", "domain": d}
    current = [x for x in current if x != d]
    _write_custom_blocks(current, header_note=f"last MCP edit: remove {d}")
    result = {"status": "removed", "domain": d, "total_custom": len(current)}
    if restart:
        result["restart"] = _restart_proxy()
    return result


@mcp.tool()
def refresh_blocklists() -> dict:
    """Fetch fresh copies of all remote blocklists declared in config.yaml.

    Does not restart the proxy on its own; restarts are triggered separately
    via `restart_proxy()` or by `add_block`/`remove_block` with restart=True.
    """
    r = subprocess.run(
        [str(_LAUNCHER), "refresh-blocklists"],
        capture_output=True, text=True,
    )
    return {
        "exit_code": r.returncode,
        "stdout_tail": (r.stdout or "").splitlines()[-10:],
        "stderr_tail": (r.stderr or "").splitlines()[-10:],
    }


@mcp.tool()
def restart_proxy() -> dict:
    """Restart the proxy (picks up any blocklist or config changes)."""
    return _restart_proxy()


@mcp.tool()
def start_proxy() -> dict:
    """Start the proxy if it isn't running (systemd preferred)."""
    if _systemd_available():
        r = subprocess.run(
            ["systemctl", "--user", "start", _SERVICE],
            capture_output=True, text=True,
        )
        return {"status": "started" if r.returncode == 0 else "error",
                "via": "systemd",
                "stderr": (r.stderr or "").strip()[:400]}
    return {"status": "error", "error":
            "no systemd unit installed; start manually with './empathymachine start'"}


def _run_launcher(subcommand: str) -> dict:
    """Shell out to the launcher (covers OS detection, gsettings/networksetup, etc.)."""
    r = subprocess.run(
        [str(_LAUNCHER), subcommand],
        capture_output=True, text=True,
    )
    return {
        "exit_code": r.returncode,
        "stdout": (r.stdout or "").strip(),
        "stderr": (r.stderr or "").strip(),
    }


@mcp.tool()
def system_proxy_on() -> dict:
    """Turn the OS-level system proxy ON (route all HTTP/HTTPS through EmpathyMachine).

    On macOS uses `networksetup` against the active network service. On Linux
    GNOME uses `gsettings`, on KDE uses `kwriteconfig`. Some apps cache the
    proxy at start — restart browsers if traffic doesn't appear to route.
    """
    return _run_launcher("proxy-on")


@mcp.tool()
def system_proxy_off() -> dict:
    """Turn the OS-level system proxy OFF (stop routing through EmpathyMachine).

    The proxy service itself keeps running; only the system's pointer to it
    is cleared. Use `stop_proxy()` to also stop the service.
    """
    return _run_launcher("proxy-off")


@mcp.tool()
def system_proxy_status() -> dict:
    """Report the current OS-level proxy configuration."""
    return _run_launcher("proxy-status")


@mcp.tool()
def bypass_host(host: str) -> dict:
    """Add a host to tls.bypass_hosts and restart the proxy.

    Use when a specific site breaks under TLS interception (banking,
    work SSO, anything with cert pinning). The host bypasses MITM but
    still goes through the proxy at the network layer.
    """
    r = subprocess.run([str(_LAUNCHER), "bypass", host], capture_output=True, text=True)
    return {"exit_code": r.returncode,
            "stdout": (r.stdout or "").strip(),
            "stderr": (r.stderr or "").strip()}


@mcp.tool()
def unbypass_host(host: str) -> dict:
    """Remove a host from tls.bypass_hosts (re-enables MITM for it)."""
    r = subprocess.run([str(_LAUNCHER), "unbypass", host], capture_output=True, text=True)
    return {"exit_code": r.returncode,
            "stdout": (r.stdout or "").strip(),
            "stderr": (r.stderr or "").strip()}


@mcp.tool()
def list_bypass_hosts() -> dict:
    """Return every host currently in tls.bypass_hosts."""
    r = subprocess.run([str(_LAUNCHER), "bypass-list"], capture_output=True, text=True)
    hosts = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()]
    return {"count": len(hosts), "hosts": hosts}


@mcp.tool()
def policy_show(name: str = "") -> dict:
    """Show captain's policy decisions from policy.yaml.

    Empty `name` returns the summary list. Specific name returns the full
    entry including the captured reasoning. policy.yaml is the source of
    truth for captain's privacy/control choices with traceable reasoning.
    See DESIGN.md sections 2 + 4.
    """
    args = [str(_LAUNCHER), "policy", "show"]
    if name:
        args.append(name)
    r = subprocess.run(args, capture_output=True, text=True)
    return {"exit_code": r.returncode,
            "stdout": (r.stdout or "").strip(),
            "stderr": (r.stderr or "").strip()}


@mcp.tool()
def policy_set(name: str, value, note: str, review_by: str = "",
               substrates: str = "em-rewriter") -> dict:
    """Create or update a policy entry.

    Every policy decision MUST capture reasoning in `note` — this is the
    audit-trail load-bearing element. `review_by` defaults to 6 months
    from today if omitted. After setting, run policy_compile(apply=True,
    restart=True) to enforce the change.

    Args:
        name: short identifier (e.g., "block_quic", "block_dot")
        value: true/false/string — the decision
        note: REQUIRED — capture WHY this decision was made (the conversation,
              the trade-off, the priority being honored). Multi-line ok.
        review_by: YYYY-MM-DD when this decision should be re-evaluated.
        substrates: comma-separated list of consumers (default: em-rewriter).
    """
    args = [str(_LAUNCHER), "policy", "set", name, str(value),
            "--note", note, "--decided-by", "captain via Claude"]
    if review_by:
        args.extend(["--review", review_by])
    if substrates:
        args.extend(["--substrates", substrates])
    r = subprocess.run(args, capture_output=True, text=True)
    return {"exit_code": r.returncode,
            "stdout": (r.stdout or "").strip(),
            "stderr": (r.stderr or "").strip()}


@mcp.tool()
def policy_compile(apply: bool = False, restart: bool = False) -> dict:
    """Propagate policy.yaml decisions into config.yaml runtime flags.

    Default is dry-run — shows what would change without writing. Set
    apply=True to write config.yaml. Set restart=True to also bounce EM
    so changes take effect immediately.
    """
    args = [str(_LAUNCHER), "policy", "compile"]
    if apply:
        args.append("--apply")
    if restart:
        args.append("--restart")
    r = subprocess.run(args, capture_output=True, text=True)
    return {"exit_code": r.returncode,
            "stdout": (r.stdout or "").strip(),
            "stderr": (r.stderr or "").strip()}


@mcp.tool()
def policy_why(name: str) -> dict:
    """Return the captured reasoning trace for a single policy decision."""
    r = subprocess.run([str(_LAUNCHER), "policy", "why", name],
                       capture_output=True, text=True)
    return {"exit_code": r.returncode,
            "stdout": (r.stdout or "").strip(),
            "stderr": (r.stderr or "").strip()}


@mcp.tool()
def policy_review() -> dict:
    """List policy entries past their review_by date or due within 30 days."""
    r = subprocess.run([str(_LAUNCHER), "policy", "review"],
                       capture_output=True, text=True)
    return {"exit_code": r.returncode,
            "stdout": (r.stdout or "").strip(),
            "stderr": (r.stderr or "").strip()}


@mcp.tool()
def explain_host(host: str, no_llm: bool = False) -> dict:
    """Look up a hostname's owner, tracker classification, and breakage impact.

    Two-tier lookup: DuckDuckGo Tracker Radar first (1k known trackers + 5.5k
    domain→owner mappings), then LLM fallback (Anthropic Claude API or local
    Ollama) for hosts DDG doesn't cover. Results from LLM are cached so repeat
    lookups are free.

    Returns JSON with owner, category, prevalence, fingerprinting score,
    suggested verdict (BLOCK / REVIEW / SAFE-TO-ALLOW), and reasoning.

    Set no_llm=True to skip the LLM fallback and only report DDG matches.
    """
    args = [str(_LAUNCHER), "explain", host, "--json"]
    if no_llm:
        args.append("--no-llm")
    r = subprocess.run(args, capture_output=True, text=True)
    out = (r.stdout or "").strip()
    err = (r.stderr or "").strip()
    try:
        return json.loads(out) if out else {"error": err, "exit_code": r.returncode}
    except Exception:
        return {"raw_stdout": out, "raw_stderr": err, "exit_code": r.returncode}


@mcp.tool()
def import_littlesnitch(export_path: str, apply: bool = False,
                        restart: bool = False) -> dict:
    """Import Little Snitch rules from a JSON export.

    Reads a Little Snitch export (LS app → File → Export Rules… → JSON),
    extracts deny-any-process rules into blocklists/littlesnitch_imports.txt,
    and registers that file in config.yaml. Per-process rules are skipped
    (EM has no process awareness).

    Default is dry-run — set apply=True to actually write files, and
    restart=True to bounce the proxy so new blocks take effect.
    """
    args = [str(_LAUNCHER), "import-littlesnitch", export_path]
    if apply:
        args.append("--apply")
    if restart:
        args.append("--restart")
    r = subprocess.run(args, capture_output=True, text=True)
    return {
        "exit_code": r.returncode,
        "stdout": (r.stdout or "").strip(),
        "stderr": (r.stderr or "").strip(),
    }


@mcp.tool()
def stop_proxy() -> dict:
    """Stop the proxy."""
    if _systemd_available():
        r = subprocess.run(
            ["systemctl", "--user", "stop", _SERVICE],
            capture_output=True, text=True,
        )
        return {"status": "stopped" if r.returncode == 0 else "error",
                "via": "systemd",
                "stderr": (r.stderr or "").strip()[:400]}
    r = subprocess.run(
        [str(_LAUNCHER), "stop"], capture_output=True, text=True,
    )
    return {"status": "stopped" if r.returncode == 0 else "error",
            "via": "launcher",
            "stdout": (r.stdout or "").strip()[:200]}


if __name__ == "__main__":
    mcp.run()
