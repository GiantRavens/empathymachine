#!/usr/bin/env python3
"""Add or remove a host from config.yaml's tls.bypass_hosts list.

Preserves all comments, formatting, and ordering — operates as a
line-level insert/remove rather than YAML round-trip. The bypass_hosts
block is the only part of config.yaml we touch.

Usage:
    python3 edit_config_bypass.py add <host>
    python3 edit_config_bypass.py remove <host>
    python3 edit_config_bypass.py list

Exit codes:
    0 — success (added/removed/already-present/not-present)
    1 — config.yaml missing or bypass_hosts block not found
    2 — invalid host
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_CONFIG = _HERE.parent / "config.yaml"

_DOMAIN_RE = re.compile(
    r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)


def _validate(host: str) -> str:
    h = host.strip().lower()
    if not h or not _DOMAIN_RE.match(h):
        print(f"invalid host: {host!r}", file=sys.stderr)
        sys.exit(2)
    return h


def _read_lines() -> list[str]:
    if not _CONFIG.exists():
        print(f"config.yaml not found at {_CONFIG}", file=sys.stderr)
        sys.exit(1)
    return _CONFIG.read_text().splitlines(keepends=True)


def _find_bypass_block(lines: list[str]) -> tuple[int, int]:
    """Return (start_idx, end_idx) where end_idx is the index AFTER the last
    `    - "..."` line in the bypass_hosts block. Raises if not found."""
    start = None
    for i, ln in enumerate(lines):
        if re.match(r"^\s*bypass_hosts:\s*$", ln):
            start = i + 1
            break
    if start is None:
        print("could not find 'bypass_hosts:' in config.yaml", file=sys.stderr)
        sys.exit(1)
    # End is the first line that's not a list item or comment at the same indent
    end = start
    while end < len(lines):
        ln = lines[end]
        if re.match(r"^\s{4,}-\s", ln) or re.match(r"^\s*#", ln) or ln.strip() == "":
            end += 1
            continue
        break
    return start, end


def _list_entries(lines: list[str], start: int, end: int) -> list[tuple[int, str]]:
    """Return [(line_idx, host), ...] for each list entry."""
    out = []
    for i in range(start, end):
        m = re.match(r'^\s{4,}-\s+["\']?([^"\'#\n]+)["\']?\s*$', lines[i])
        if m:
            out.append((i, m.group(1).strip()))
    return out


def cmd_list() -> None:
    lines = _read_lines()
    start, end = _find_bypass_block(lines)
    entries = _list_entries(lines, start, end)
    for _, host in entries:
        print(host)


def cmd_add(host: str) -> None:
    h = _validate(host)
    lines = _read_lines()
    start, end = _find_bypass_block(lines)
    entries = _list_entries(lines, start, end)
    if any(e[1].lower() == h for e in entries):
        print(f"already present: {h}")
        return
    # Insert at the position right after the last list entry (or at end of block)
    insert_at = entries[-1][0] + 1 if entries else start
    # Determine indent from existing entries; default to 4 spaces
    indent = "    "
    if entries:
        m = re.match(r"^(\s+)-", lines[entries[-1][0]])
        if m:
            indent = m.group(1)
    new_line = f'{indent}- "{h}"\n'
    lines.insert(insert_at, new_line)
    _CONFIG.write_text("".join(lines))
    print(f"added: {h}")


def cmd_remove(host: str) -> None:
    h = _validate(host)
    lines = _read_lines()
    start, end = _find_bypass_block(lines)
    entries = _list_entries(lines, start, end)
    matches = [i for i, e in entries if e.lower() == h]
    if not matches:
        print(f"not present: {h}")
        return
    # Remove in reverse so indices stay valid
    for idx in reversed(matches):
        lines.pop(idx)
    _CONFIG.write_text("".join(lines))
    print(f"removed: {h} ({len(matches)} entries)")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 1
    action = sys.argv[1]
    if action == "list":
        cmd_list()
    elif action in ("add", "remove") and len(sys.argv) == 3:
        (cmd_add if action == "add" else cmd_remove)(sys.argv[2])
    else:
        print(__doc__, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
