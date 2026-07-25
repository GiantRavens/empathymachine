#!/usr/bin/env python3
"""Import Little Snitch rules into EmpathyMachine.

Reads a Little Snitch JSON export (in the LS app: File → Export Rules…
choose JSON format) and splits its rules into two EmpathyMachine artifacts:

  - deny-any-process rules     → blocklists/littlesnitch_imports.txt
  - allow-any-process rules    → proposed additions to tls.bypass_hosts
  - per-process rules          → skipped (EM has no process awareness)

The premise: LS gathers the captain's per-app firewall decisions on macOS;
EM enforces hostname-level decisions across DNS + HTTP everywhere (Linux,
Pi, LAN). Per-process LS rules don't translate (EM can't tell which
process made a request), but any-process rules carry the captain's vetted
'block this domain everywhere' or 'allow this domain everywhere' intent —
exactly what EM wants in its blocklist + bypass list.

Idempotent. Reads state/last_ls_import.json on each run so re-imports
show deltas instead of bulk-rewriting.

Usage:
    python3 import_littlesnitch.py <ls-export.json>             # dry-run, show diff
    python3 import_littlesnitch.py <ls-export.json> --apply     # write files
    python3 import_littlesnitch.py <ls-export.json> --apply --restart   # + restart EM
    python3 import_littlesnitch.py --inspect <ls-export.json>   # dump rule shape, for debugging

Format tolerance: handles Little Snitch 4.x and 5.x JSON variants. If
your export has an unrecognized shape, run --inspect first and send the
output; the parser is easy to extend.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PROJECT_ROOT = _HERE.parent
_BLOCKLIST_PATH = _PROJECT_ROOT / "blocklists" / "littlesnitch_imports.txt"
_CONFIG_PATH = _PROJECT_ROOT / "config.yaml"
_STATE_PATH = _PROJECT_ROOT / "state" / "last_ls_import.json"
_BLOCKLIST_HEADER = """# blocklists/littlesnitch_imports.txt — managed by import_littlesnitch.py
# DO NOT EDIT BY HAND. Re-run `mm import-littlesnitch <export.json>` to refresh.
# Source rules come from Little Snitch with action=deny, scope=any-process.
"""

# Match a hostname with optional leading '*.' wildcard. Same shape as
# EM's bypass validator so anything we propose is acceptable to that side.
_HOST_RE = re.compile(
    r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)


# ─── LS rule parsing ─────────────────────────────────────────────────────

def _load(path: Path) -> dict | list:
    try:
        return json.loads(path.read_text())
    except Exception as e:
        sys.exit(f"failed to read LS export at {path}: {e}")


def _rules_array(blob: dict | list) -> list[dict]:
    """LS export variants put the rules array in different places. Find it."""
    if isinstance(blob, list):
        return blob
    if isinstance(blob, dict):
        for key in ("rules", "Rules", "ruleData", "data"):
            if isinstance(blob.get(key), list):
                return blob[key]
        # LS 5 sometimes nests under "subscriptions" -> "rules"
        for sub in blob.values():
            if isinstance(sub, list):
                return sub
            if isinstance(sub, dict) and isinstance(sub.get("rules"), list):
                return sub["rules"]
    return []


def _action(rule: dict) -> str:
    """Normalize action to 'deny' | 'allow' | 'ask' | 'suggestion' | 'unknown'."""
    raw = (rule.get("action") or rule.get("verdict") or "").strip().lower()
    if raw in ("deny", "block", "reject"):
        return "deny"
    if raw in ("allow", "permit", "accept"):
        return "allow"
    if raw == "ask":
        return "ask"
    if raw == "suggestion":
        # LS 5/6 marks unconfirmed auto-detected rules as "suggestion".
        # Treated separately so they don't pollute the "unknown_action" count.
        return "suggestion"
    return "unknown"


def _hosts(rule: dict) -> list[str]:
    """Pull hostnames from any of the keys LS has used over versions.

    LS 6 commonly uses `remote: "any"` (literal string) to mean "any
    remote address" — that's not a hostname, it's the absence of one,
    so it's filtered out here.
    """
    candidates: list[str] = []
    for key in ("remote-hosts", "remoteHosts", "remoteHost", "remote-host",
                "hostname", "hostnames", "remote-domain", "remoteDomain"):
        val = rule.get(key)
        if isinstance(val, str):
            candidates.append(val)
        elif isinstance(val, list):
            candidates.extend(v for v in val if isinstance(v, str))
    # LS sometimes encodes a single endpoint object under "remote": {"host": "..."}
    rem = rule.get("remote")
    if isinstance(rem, dict):
        for key in ("host", "hostname", "domain"):
            v = rem.get(key)
            if isinstance(v, str):
                candidates.append(v)
    # If `remote` is the literal string "any" or "*", that means "any address" —
    # no hostname to extract.
    return candidates


def _is_any_process(rule: dict) -> bool:
    """True if the rule applies to any process. LS 6 uses several shapes:
       - process omitted / null  → any
       - process == "Any Process" / "any" / "*"  → any
       - process == "identifier.XXX/com.something"  → SPECIFIC process (bundle ID)
       - process == "/absolute/path"  → SPECIFIC process
    """
    proc = rule.get("process")
    if proc is None:
        return True
    if isinstance(proc, str):
        s = proc.strip().lower()
        if s in ("any process", "any", "*", "any-process", ""):
            return True
    return False


def _valid_hostname(s: str) -> str | None:
    """Normalize and validate. Returns lowercased hostname or None to skip."""
    s = s.strip().rstrip(".")
    if not s:
        return None
    # Skip explicit IPs — EM operates on hostnames, not IPs.
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", s):
        return None
    if ":" in s and not s.startswith("*."):  # likely IPv6 or has port
        return None
    # LS uses "any-domain" or empty as wildcard — skip, those would block
    # or allow everything.
    if s.lower() in ("any-domain", "any", "*"):
        return None
    s = s.lower()
    return s if _HOST_RE.match(s) else None


# ─── classification ──────────────────────────────────────────────────────

class Summary:
    def __init__(self) -> None:
        self.total_rules: int = 0
        self.skipped_per_process: int = 0
        self.skipped_unknown_action: int = 0
        self.skipped_no_host: int = 0
        self.skipped_invalid_host: int = 0
        self.skipped_ask: int = 0
        self.skipped_suggestion: int = 0
        self.deny_hosts: set[str] = set()
        self.allow_hosts: set[str] = set()
        # Diagnostic: count per-process rules by process for inspection
        self.per_process_counter: Counter[str] = Counter()
        # Diagnostic: count any-process deny/allow that have no usable host
        # (LS 6 commonly: remote="any" literal string; nothing to import)
        self.any_process_no_host: int = 0

    def as_dict(self) -> dict:
        return {
            "total_rules": self.total_rules,
            "skipped_per_process": self.skipped_per_process,
            "skipped_unknown_action": self.skipped_unknown_action,
            "skipped_no_host": self.skipped_no_host,
            "skipped_invalid_host": self.skipped_invalid_host,
            "skipped_ask": self.skipped_ask,
            "skipped_suggestion": self.skipped_suggestion,
            "any_process_no_host": self.any_process_no_host,
            "deny_count": len(self.deny_hosts),
            "allow_count": len(self.allow_hosts),
            "top_per_process": self.per_process_counter.most_common(5),
        }


def classify(rules: list[dict]) -> Summary:
    s = Summary()
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        s.total_rules += 1

        action = _action(rule)
        if action == "ask":
            s.skipped_ask += 1
            continue
        if action == "suggestion":
            s.skipped_suggestion += 1
            continue
        if action == "unknown":
            s.skipped_unknown_action += 1
            continue

        if not _is_any_process(rule):
            s.skipped_per_process += 1
            proc = rule.get("process")
            if isinstance(proc, str):
                s.per_process_counter[proc] += 1
            continue

        hosts = _hosts(rule)
        if not hosts:
            # Any-process deny/allow without a hostname. LS 6 typical:
            # remote: "any" → block/allow regardless of address. EM can't
            # represent that without a hostname pattern. Count separately
            # so the dry-run report shows it as "expected skip" not bug.
            s.any_process_no_host += 1
            continue

        any_valid = False
        for h in hosts:
            v = _valid_hostname(h)
            if v is None:
                continue
            any_valid = True
            if action == "deny":
                s.deny_hosts.add(v)
            elif action == "allow":
                s.allow_hosts.add(v)
        if not any_valid:
            s.skipped_invalid_host += 1
    return s


# ─── writers ─────────────────────────────────────────────────────────────

def write_blocklist(hosts: set[str]) -> None:
    _BLOCKLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    lines = [_BLOCKLIST_HEADER,
             f"# Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
             f"# Count: {len(hosts)}",
             ""]
    for h in sorted(hosts):
        lines.append(f"0.0.0.0 {h}")
    _BLOCKLIST_PATH.write_text("\n".join(lines) + "\n")


def ensure_blocklist_registered() -> bool:
    """Make sure config.yaml's blocklists: list includes our file. Returns True if added."""
    if not _CONFIG_PATH.exists():
        return False
    rel = "blocklists/littlesnitch_imports.txt"
    text = _CONFIG_PATH.read_text()
    # Already registered?
    if rel in text:
        return False
    # Find the "blocklists:" block and inject our line.
    lines = text.splitlines(keepends=True)
    out = []
    in_block = False
    injected = False
    for ln in lines:
        out.append(ln)
        if re.match(r"^blocklists:\s*$", ln):
            in_block = True
            continue
        if in_block and not injected:
            # Inject after the LAST existing list entry, or right after the
            # 'blocklists:' line if list is empty.
            if not re.match(r"^\s+-\s", ln) and not re.match(r"^\s*#", ln) and ln.strip() != "":
                # We've fallen off the end of the list — inject before this line
                out.insert(-1, f'  - "{rel}"\n')
                injected = True
                in_block = False
    if in_block and not injected:
        out.append(f'  - "{rel}"\n')
        injected = True
    if injected:
        _CONFIG_PATH.write_text("".join(out))
    return injected


# ─── state persistence ──────────────────────────────────────────────────

def load_prior_state() -> dict:
    if not _STATE_PATH.exists():
        return {}
    try:
        return json.loads(_STATE_PATH.read_text())
    except Exception:
        return {}


def save_state(summary: Summary, source_path: Path) -> None:
    _STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _STATE_PATH.write_text(json.dumps({
        "imported_utc": datetime.now(timezone.utc).isoformat(timespec='seconds'),
        "source": str(source_path.resolve()),
        "deny_hosts": sorted(summary.deny_hosts),
        "allow_hosts": sorted(summary.allow_hosts),
        "summary": summary.as_dict(),
    }, indent=2))


# ─── inspector ──────────────────────────────────────────────────────────

def inspect(path: Path) -> None:
    """Diagnostic mode: print the top-level structure of the export so the
    parser can be extended if your LS version has an unrecognized format."""
    blob = _load(path)
    if isinstance(blob, dict):
        print(f"top-level: dict with keys {list(blob.keys())}")
        for k, v in blob.items():
            if isinstance(v, list):
                print(f"  {k}: list of {len(v)} items")
                if v:
                    print(f"    [0] = {json.dumps(v[0], indent=2)[:500]}")
                    break
            elif isinstance(v, dict):
                print(f"  {k}: dict with keys {list(v.keys())}")
    elif isinstance(blob, list):
        print(f"top-level: list of {len(blob)} items")
        if blob:
            print(f"  [0] = {json.dumps(blob[0], indent=2)[:500]}")
    rules = _rules_array(blob)
    print(f"\ndetected rules array: {len(rules)} entries")
    if rules:
        sample = rules[0]
        print(f"sample rule keys: {sorted(sample.keys()) if isinstance(sample, dict) else 'non-dict'}")


# ─── main ───────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("export", type=Path, help="LS JSON export file")
    p.add_argument("--apply", action="store_true",
                   help="Write blocklist file + register in config.yaml (default: dry-run)")
    p.add_argument("--restart", action="store_true",
                   help="Restart EmpathyMachine after applying")
    p.add_argument("--inspect", action="store_true",
                   help="Dump export structure for parser debugging, then exit")
    args = p.parse_args(argv)

    if not args.export.exists():
        sys.exit(f"export file not found: {args.export}")

    if args.inspect:
        inspect(args.export)
        return 0

    blob = _load(args.export)
    rules = _rules_array(blob)
    if not rules:
        sys.exit("could not locate a rules array in this export. Run with --inspect for details.")

    summary = classify(rules)

    prior = load_prior_state()
    prior_deny = set(prior.get("deny_hosts", []))
    prior_allow = set(prior.get("allow_hosts", []))
    added_deny = summary.deny_hosts - prior_deny
    removed_deny = prior_deny - summary.deny_hosts
    added_allow = summary.allow_hosts - prior_allow
    removed_allow = prior_allow - summary.allow_hosts

    print(f"=== Little Snitch import ({args.export}) ===")
    print(f"  total rules:                            {summary.total_rules}")
    print(f"  skipped (suggestion — LS unconfirmed):  {summary.skipped_suggestion}")
    print(f"  skipped (per-process — not EM-able):    {summary.skipped_per_process}")
    print(f"  skipped (any-process, no hostname):     {summary.any_process_no_host}")
    print(f"  skipped (ask):                          {summary.skipped_ask}")
    print(f"  skipped (no/invalid host):              "
          f"{summary.skipped_no_host + summary.skipped_invalid_host}")
    print(f"  skipped (unknown action):               {summary.skipped_unknown_action}")
    print(f"  → deny  (any-process, has host):        {len(summary.deny_hosts)}")
    print(f"  → allow (any-process, has host):        {len(summary.allow_hosts)}")
    if summary.per_process_counter:
        print(f"\n  per-process rules (skipped) by top binary:")
        for proc, n in summary.per_process_counter.most_common(5):
            print(f"    {n:4d}  {proc}")

    if prior:
        print(f"\n  delta vs previous import:")
        print(f"    deny  added: {len(added_deny):4d}  removed: {len(removed_deny):4d}")
        print(f"    allow added: {len(added_allow):4d}  removed: {len(removed_allow):4d}")
        if added_deny:
            print(f"    new deny hosts (first 10):")
            for h in sorted(added_deny)[:10]:
                print(f"      + {h}")

    if not args.apply:
        print(f"\n(dry-run — pass --apply to write {_BLOCKLIST_PATH.name})")
        if summary.allow_hosts:
            print(f"(allow-host candidates: run with --apply to see the proposed "
                  f"tls.bypass_hosts additions)")
        return 0

    # Apply
    write_blocklist(summary.deny_hosts)
    print(f"\n✓ wrote {len(summary.deny_hosts)} hosts → {_BLOCKLIST_PATH}")

    if ensure_blocklist_registered():
        print(f"✓ registered {_BLOCKLIST_PATH.name} in {_CONFIG_PATH.name}")
    else:
        print(f"  ({_BLOCKLIST_PATH.name} already registered in {_CONFIG_PATH.name})")

    save_state(summary, args.export)

    if summary.allow_hosts:
        print(f"\nAllow-host candidates for tls.bypass_hosts (not auto-added —")
        print(f"these are LS allow rules and may not all warrant MITM bypass):")
        for h in sorted(summary.allow_hosts):
            print(f"  - {h}")
        print(f"\nTo bypass any of these in EM:  mm bypass <host>")

    if args.restart:
        import subprocess
        launcher = _PROJECT_ROOT / "empathymachine"
        r = subprocess.run([str(launcher), "restart"], capture_output=True, text=True)
        print("\n" + (r.stdout or "").strip())
        if r.returncode != 0:
            print((r.stderr or "").strip(), file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
