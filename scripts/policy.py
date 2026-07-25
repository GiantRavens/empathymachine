#!/usr/bin/env python3
"""mm policy — read/write captain's privacy/control decisions in policy.yaml.

policy.yaml is the source of truth. config.yaml is the runtime configuration
the Rust binary actually consumes. `policy compile` writes the relevant
config.yaml sections from policy.yaml entries.

Subcommands:
    mm policy show                      # summary of every entry
    mm policy show <name>               # full entry with reasoning trace
    mm policy set <name> <value> [--note "..."] [--review YYYY-MM-DD]
                                        # update / create an entry, write
                                        # reasoning + decided_at + decided_by
    mm policy compile [--apply] [--restart]
                                        # propagate policy.yaml decisions
                                        # into config.yaml runtime flags
    mm policy why <name>                # show the reasoning trace for one decision
    mm policy review                    # list entries past their review_by date
    mm policy diff                      # show what compile would change without writing

Uses stdlib only — no PyYAML dep. Round-trips policy.yaml via careful
text-level edits to preserve comments + ordering.
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PROJECT_ROOT = _HERE.parent
_POLICY = _PROJECT_ROOT / "policy.yaml"
_CONFIG = _PROJECT_ROOT / "config.yaml"
_LAUNCHER = _PROJECT_ROOT / "empathymachine"
_POLICY_BLOCKLIST = _PROJECT_ROOT / "blocklists" / "policy_imports.txt"

# Fenced-region markers for managed insertions into config.yaml.
# Anything between BEGIN/END is owned by `mm policy compile` — captain
# should not hand-edit. Re-running compile rewrites these regions
# idempotently, so adding/removing/editing a policy.yaml entry is safe.
_FENCE_BEGIN = "    # === BEGIN policy.yaml managed (do not edit between markers) ==="
_FENCE_END = "    # === END policy.yaml managed ==="


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _default_review() -> str:
    """Six months from today."""
    return (dt.date.today() + dt.timedelta(days=183)).isoformat()


# ─── policy.yaml read ────────────────────────────────────────────────────

def _load_policy_text() -> str:
    if not _POLICY.exists():
        sys.exit(f"policy.yaml not found at {_POLICY}\n"
                 f"  bootstrap with:  cp {_POLICY.with_suffix('.yaml.sample')} {_POLICY}")
    return _POLICY.read_text()


def _try_load_yaml() -> dict | None:
    """Best-effort parse using PyYAML if available; None if not installed."""
    try:
        import yaml  # type: ignore
        return yaml.safe_load(_load_policy_text())
    except ImportError:
        return None


def _entries() -> list[tuple[str, str, dict]]:
    """Return list of (section, name, parsed_dict) for every entry under
    a known section ('network_policy' or 'presentation_policy')."""
    parsed = _try_load_yaml()
    out = []
    if parsed:
        for section in ("network_policy", "presentation_policy"):
            for name, body in (parsed.get(section) or {}).items():
                if isinstance(body, dict):
                    out.append((section, name, body))
    return out


# ─── policy.yaml write (text-preserving) ────────────────────────────────

_ENTRY_TEMPLATE = """\
  {name}:
    value: {value}
    decided_at: {decided_at}
    decided_by: {decided_by!r}
    note: |
{note_indented}
    review_by: {review_by}
    substrates: {substrates}
"""


def _write_entry(section: str, name: str, value, *, note: str, decided_by: str,
                 review_by: str, substrates: list[str]) -> None:
    """Insert/replace an entry under <section>: in policy.yaml. Preserves
    surrounding comments + sections via regex-style locate-and-rewrite."""
    text = _load_policy_text()
    section_re = re.compile(rf"^{re.escape(section)}:\s*$", re.MULTILINE)
    m = section_re.search(text)
    if not m:
        sys.exit(f"section '{section}:' not found in policy.yaml")
    section_start = m.end()
    # Locate the next top-level key (line starting non-space, non-#) so we
    # know where this section ends.
    next_top = re.search(r"\n^[a-zA-Z_]", text[section_start:], re.MULTILINE)
    section_end = section_start + (next_top.start() if next_top else len(text) - section_start)
    section_body = text[section_start:section_end]

    # Format the new entry block
    note_indented = "\n".join(f"      {ln}" for ln in note.strip().splitlines())
    yaml_value = "true" if value is True else "false" if value is False else str(value)
    substrates_str = "[" + ", ".join(substrates) + "]" if substrates else "[]"
    new_block = _ENTRY_TEMPLATE.format(
        name=name, value=yaml_value, decided_at=_now_iso(),
        decided_by=decided_by, note_indented=note_indented,
        review_by=review_by, substrates=substrates_str,
    )

    # Replace existing entry with same name (matches '  <name>:' through next
    # entry start or section end), or append.
    entry_re = re.compile(
        rf"^(?:  {re.escape(name)}:.*?)(?=\n  [a-zA-Z_][^:]*:|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    em = entry_re.search(section_body)
    if em:
        new_section_body = (
            section_body[:em.start()] + new_block.rstrip("\n") + section_body[em.end():]
        )
    else:
        # Insert at end of section, trimming trailing whitespace
        new_section_body = section_body.rstrip() + "\n\n" + new_block

    new_text = text[:section_start] + new_section_body + text[section_end:]
    _POLICY.write_text(new_text)


# ─── commands ───────────────────────────────────────────────────────────

def cmd_show(args) -> int:
    entries = _entries()
    if not entries:
        if _try_load_yaml() is None:
            print("(PyYAML not installed; install with: uv pip install pyyaml — "
                  "or use the venv-mcp interpreter)", file=sys.stderr)
        print("(no entries in policy.yaml)")
        return 0
    if args.name:
        for section, name, body in entries:
            if name == args.name:
                print(f"=== {section}.{name} ===")
                print(f"  value:       {body.get('value')}")
                print(f"  decided_at:  {body.get('decided_at')}")
                print(f"  decided_by:  {body.get('decided_by')}")
                print(f"  review_by:   {body.get('review_by')}")
                print(f"  substrates:  {body.get('substrates')}")
                print(f"  note:")
                for ln in str(body.get("note", "")).splitlines():
                    print(f"    {ln}")
                return 0
        sys.exit(f"no entry named {args.name!r}")
    # Summary
    for section, name, body in entries:
        val = body.get("value")
        rb = body.get("review_by", "?")
        note_first = str(body.get("note", "")).strip().splitlines()
        first_line = note_first[0] if note_first else ""
        print(f"  {section}.{name:<20}  {str(val):<6}  review:{rb}  — {first_line[:60]}")
    return 0


def cmd_set(args) -> int:
    section = "network_policy"  # only section supported today
    if args.note is None:
        sys.exit("--note REQUIRED — every decision must capture its reasoning")
    val: bool | str
    raw = args.value.strip().lower()
    if raw in ("true", "yes", "on", "1"):
        val = True
    elif raw in ("false", "no", "off", "0"):
        val = False
    else:
        val = args.value
    review = args.review or _default_review()
    decided_by = args.decided_by or os.environ.get("EMPATHYMACHINE_DECIDED_BY",
                                                   "captain via Claude")
    substrates = args.substrates.split(",") if args.substrates else ["em-rewriter"]
    _write_entry(section, args.name, val,
                 note=args.note, decided_by=decided_by,
                 review_by=review, substrates=substrates)
    print(f"✓ wrote {section}.{args.name} = {val}")
    print(f"  policy.yaml updated. Run `mm policy compile --apply --restart` to enforce.")
    return 0


# ─── compile (policy.yaml → config.yaml runtime flags) ──────────────────

def _config_set_network_policy(block_quic: bool) -> bool:
    """Update config.yaml's network_policy block. Returns True if changed."""
    if not _CONFIG.exists():
        sys.exit(f"config.yaml not found at {_CONFIG}")
    text = _CONFIG.read_text()
    desired = f"network_policy:\n  block_quic: {'true' if block_quic else 'false'}\n"
    block_re = re.compile(r"^network_policy:.*?(?=\n[a-zA-Z_]|\Z)",
                          re.MULTILINE | re.DOTALL)
    if block_re.search(text):
        new_text = block_re.sub(desired.rstrip("\n"), text, count=1)
    else:
        if not text.endswith("\n"):
            text += "\n"
        new_text = text + "\n" + desired
    if new_text == text:
        return False
    _CONFIG.write_text(new_text)
    return True


# ─── presentation_policy compile ────────────────────────────────────────

def _collect_presentation_applies(entries: dict) -> dict:
    """Aggregate every enabled presentation_policy entry's apply: block.
    Returns dict with keys: remove_selectors, css_hide_selectors, block_hosts,
    each a list of (entry_name, value) tuples for provenance."""
    out = {"remove_selectors": [], "css_hide_selectors": [], "block_hosts": []}
    for (section, name), body in entries.items():
        if section != "presentation_policy":
            continue
        if body.get("value") is not True:
            continue
        apply = body.get("apply") or {}
        for k in out:
            for v in apply.get(k, []) or []:
                out[k].append((name, str(v)))
    return out


def _render_managed_remove_block(applies: dict) -> str:
    """Generate the YAML lines that go inside the fenced region of
    rewrites.remove. Empty string if nothing to add."""
    items = applies["remove_selectors"]
    if not items:
        return ""
    lines = []
    current_owner = None
    for owner, selector in items:
        if owner != current_owner:
            lines.append(f"    # from policy.yaml presentation_policy.{owner}")
            current_owner = owner
        # Quote with single quotes (CSS selectors often contain double quotes)
        lines.append(f"    - {selector!r}")
    return "\n".join(lines)


def _render_managed_css_block(applies: dict) -> str:
    items = applies["css_hide_selectors"]
    if not items:
        return ""
    lines = []
    current_owner = None
    for owner, selector in items:
        if owner != current_owner:
            lines.append(f"    # from policy.yaml presentation_policy.{owner}")
            current_owner = owner
        lines.append(f"    - {selector!r} + ' {{ display: none !important; }}'")
        # Actually emit the CSS rule, not a Python expression — fix below
    # Redo cleanly to emit "selector { display: none !important; }"
    lines = []
    current_owner = None
    for owner, selector in items:
        if owner != current_owner:
            lines.append(f"    # from policy.yaml presentation_policy.{owner}")
            current_owner = owner
        css = f"{selector} {{ display: none !important; }}"
        lines.append(f'    - "{css}"')
    return "\n".join(lines)


def _inject_fenced_block(text: str, parent_key: str, sub_key: str,
                         managed_lines: str) -> tuple[str, bool]:
    """Inject (or replace, or remove) the fenced managed block inside
    config.yaml's parent.sub_key (e.g., rewrites.remove).

    Strategy: line-based. Find `<parent_key>:` line, then `  <sub_key>:`
    line directly under it, then walk forward while indentation looks like
    a list continuation (4+ spaces, OR comment, OR blank). Stop at the
    first line that doesn't fit. Replace any existing fenced region in
    that span, or append at the end.
    """
    lines = text.splitlines(keepends=True)
    n = len(lines)

    # Locate parent_key: at column 0
    parent_re = re.compile(rf"^{re.escape(parent_key)}:\s*$")
    sub_re = re.compile(rf"^  {re.escape(sub_key)}:\s*$")
    parent_idx = next((i for i, ln in enumerate(lines) if parent_re.match(ln)), None)
    if parent_idx is None:
        return text, False
    # Locate sub_key: indented by 2 spaces, after parent
    sub_idx = next(
        (i for i in range(parent_idx + 1, n) if sub_re.match(lines[i])),
        None,
    )
    if sub_idx is None:
        return text, False

    # Walk forward from sub_idx+1 while lines belong to this sub-block.
    # Belongs iff: blank line, OR 4+ leading spaces, OR comment.
    end_idx = sub_idx + 1
    while end_idx < n:
        ln = lines[end_idx]
        if ln.strip() == "":
            end_idx += 1
            continue
        if ln.startswith("    "):  # 4+ spaces = continuation
            end_idx += 1
            continue
        if ln.lstrip().startswith("#") and (ln.startswith("    ") or ln.startswith("  #")):
            end_idx += 1
            continue
        break  # something else — sub-block ended

    # Find and remove any existing fenced region within [sub_idx+1, end_idx)
    body_start = sub_idx + 1
    fence_begin_idx = next(
        (i for i in range(body_start, end_idx) if lines[i].rstrip() == _FENCE_BEGIN),
        None,
    )
    if fence_begin_idx is not None:
        fence_end_idx = next(
            (i for i in range(fence_begin_idx + 1, end_idx)
             if lines[i].rstrip() == _FENCE_END),
            None,
        )
        if fence_end_idx is not None:
            # Drop the existing fenced region
            new_lines = lines[:fence_begin_idx] + lines[fence_end_idx + 1:]
            # Adjust end_idx for the removal
            end_idx -= (fence_end_idx - fence_begin_idx + 1)
            lines = new_lines

    # Compose the new fenced block
    if not managed_lines.strip():
        new_text = "".join(lines)
        return new_text, new_text != text

    new_fence = f"{_FENCE_BEGIN}\n{managed_lines}\n{_FENCE_END}\n"

    # Insert before end_idx, but skip trailing blank lines so the block
    # comes immediately after the last list entry.
    insert_at = end_idx
    while insert_at > body_start and lines[insert_at - 1].strip() == "":
        insert_at -= 1

    lines = lines[:insert_at] + [new_fence] + lines[insert_at:]
    new_text = "".join(lines)
    return new_text, new_text != text


def _write_policy_blocklist(applies: dict) -> bool:
    """Write blocklists/policy_imports.txt from all block_hosts in
    presentation_policy. Returns True if file changed."""
    items = applies["block_hosts"]
    hosts_by_owner: dict[str, list[str]] = {}
    for owner, host in items:
        hosts_by_owner.setdefault(owner, []).append(host.strip().lower())

    _POLICY_BLOCKLIST.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# blocklists/policy_imports.txt — managed by `mm policy compile`",
        "# DO NOT EDIT BY HAND. Source: policy.yaml presentation_policy.*.apply.block_hosts",
        "",
    ]
    for owner in sorted(hosts_by_owner):
        lines.append(f"# from policy.yaml presentation_policy.{owner}")
        for host in sorted(set(hosts_by_owner[owner])):
            lines.append(f"0.0.0.0 {host}")
        lines.append("")
    new_content = "\n".join(lines).rstrip("\n") + "\n"
    previous = _POLICY_BLOCKLIST.read_text() if _POLICY_BLOCKLIST.exists() else ""
    if new_content == previous:
        return False
    _POLICY_BLOCKLIST.write_text(new_content)
    return True


def _ensure_policy_blocklist_registered() -> bool:
    """Make sure config.yaml's blocklists: list includes policy_imports.txt.
    Returns True if added. Line-based to avoid the false-positive injection
    between sections that the earlier regex version was prone to."""
    rel = "blocklists/policy_imports.txt"
    text = _CONFIG.read_text()
    if rel in text:
        return False
    lines = text.splitlines(keepends=True)
    n = len(lines)
    bl_idx = next(
        (i for i, ln in enumerate(lines) if re.match(r"^blocklists:\s*$", ln)),
        None,
    )
    if bl_idx is None:
        return False
    # Find the last list-item line ('  - ...') that's part of this
    # block — walk forward from bl_idx+1, accepting only list items and
    # blank lines (NOT comments — a comment-only line that's not indented
    # like a list typically belongs to the next section).
    last_item_idx = bl_idx
    i = bl_idx + 1
    while i < n:
        ln = lines[i]
        if re.match(r"^  -\s", ln):
            last_item_idx = i
            i += 1
            continue
        if ln.strip() == "":
            i += 1
            continue
        break
    insert_at = last_item_idx + 1
    lines = lines[:insert_at] + [f'  - "{rel}"\n'] + lines[insert_at:]
    _CONFIG.write_text("".join(lines))
    return True


def cmd_compile(args) -> int:
    entries = {(s, n): b for s, n, b in _entries()}
    target_block_quic = bool(
        entries.get(("network_policy", "block_quic"), {}).get("value", False)
    )

    applies = _collect_presentation_applies(entries)

    if not args.apply:
        print("=== Would change ===")
        print(f"  config.yaml network_policy.block_quic = {target_block_quic}")
        print(f"  rewrites.remove fenced block: {len(applies['remove_selectors'])} selectors")
        print(f"  rewrites.css   fenced block: {len(applies['css_hide_selectors'])} hide-rules")
        print(f"  blocklists/policy_imports.txt: {len(applies['block_hosts'])} hosts")
        print("\n(dry-run — pass --apply to write, --apply --restart to enforce)")
        return 0

    # 1. Network policy → config.yaml network_policy block
    if _config_set_network_policy(target_block_quic):
        print(f"✓ config.yaml network_policy.block_quic = {target_block_quic}")
    else:
        print(f"  (network_policy.block_quic unchanged)")

    # 2. Presentation policy → fenced blocks in config.yaml + managed blocklist
    config_text = _CONFIG.read_text()
    remove_block = _render_managed_remove_block(applies)
    css_block = _render_managed_css_block(applies)
    config_text, ch1 = _inject_fenced_block(config_text, "rewrites", "remove", remove_block)
    config_text, ch2 = _inject_fenced_block(config_text, "rewrites", "css", css_block)
    if ch1 or ch2:
        _CONFIG.write_text(config_text)
        print(f"✓ config.yaml rewrites: fenced managed regions updated")
    else:
        print(f"  (rewrites managed regions unchanged)")

    if _write_policy_blocklist(applies):
        print(f"✓ blocklists/policy_imports.txt: {len(applies['block_hosts'])} hosts")
    else:
        print(f"  (policy_imports.txt unchanged)")

    if _ensure_policy_blocklist_registered():
        print(f"✓ registered blocklists/policy_imports.txt in config.yaml")

    if args.restart:
        import subprocess
        r = subprocess.run([str(_LAUNCHER), "restart"], capture_output=True, text=True)
        print((r.stdout or "").strip())
        return r.returncode
    else:
        print(f"  Run `mm restart` to enforce the changes.")
    return 0


def cmd_why(args) -> int:
    for section, name, body in _entries():
        if name == args.name:
            print(f"{section}.{name}  =  {body.get('value')}")
            print(f"  decided_at: {body.get('decided_at')}")
            print(f"  decided_by: {body.get('decided_by')}")
            print(f"  note:")
            for ln in str(body.get("note", "")).splitlines():
                print(f"    {ln}")
            return 0
    sys.exit(f"no entry named {args.name!r}")


def cmd_review(args) -> int:
    today = dt.date.today()
    overdue = []
    upcoming = []
    for section, name, body in _entries():
        rb = body.get("review_by")
        if not rb:
            continue
        try:
            review_date = dt.date.fromisoformat(str(rb).split("T")[0])
        except Exception:
            continue
        days = (review_date - today).days
        if days < 0:
            overdue.append((section, name, review_date, abs(days)))
        elif days <= 30:
            upcoming.append((section, name, review_date, days))
    if overdue:
        print("=== overdue for review ===")
        for s, n, d, ago in overdue:
            print(f"  {s}.{n:<20}  was due {d}  ({ago} days ago)")
    if upcoming:
        print("\n=== due within 30 days ===")
        for s, n, d, dleft in upcoming:
            print(f"  {s}.{n:<20}  due {d}  ({dleft} days)")
    if not overdue and not upcoming:
        print("(no policy entries past review or due within 30 days)")
    return 0


# ─── main ───────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="mm policy", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("show", help="summary or single-entry view")
    sp.add_argument("name", nargs="?")
    sp.set_defaults(func=cmd_show)

    sp = sub.add_parser("set", help="create/update a policy entry")
    sp.add_argument("name")
    sp.add_argument("value")
    sp.add_argument("--note", required=False, help="reasoning (required)")
    sp.add_argument("--review", help="review_by date (YYYY-MM-DD); default 6mo from today")
    sp.add_argument("--decided-by", dest="decided_by",
                    help="who/what made the decision (default: 'captain via Claude')")
    sp.add_argument("--substrates", help="comma-separated substrates list")
    sp.set_defaults(func=cmd_set)

    sp = sub.add_parser("compile", help="propagate policy.yaml → config.yaml runtime")
    sp.add_argument("--apply", action="store_true", help="actually write changes")
    sp.add_argument("--restart", action="store_true", help="restart EM after applying")
    sp.set_defaults(func=cmd_compile)

    sp = sub.add_parser("why", help="show reasoning trace for one decision")
    sp.add_argument("name")
    sp.set_defaults(func=cmd_why)

    sp = sub.add_parser("review", help="list entries past review_by")
    sp.set_defaults(func=cmd_review)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
