#!/usr/bin/env python3
"""Explain a hostname: owner, tracker classification, breakage impact, verdict.

Two-tier lookup:
  1. DuckDuckGo Tracker Radar (offline cache at ~/.empathymachine/tracker-radar/tds.json)
     — covers ~1k known trackers + ~5.5k domain→owner mappings.
  2. LLM fallback (Anthropic Claude API via ANTHROPIC_API_KEY, or local
     Ollama at 127.0.0.1:11434 if no API key) — for long-tail hosts DDG
     doesn't classify (CDNs, niche services, recently-introduced hosts).
     Cached to ~/.empathymachine/host-cache.sqlite so repeat lookups are free.

Designed for the Alert+Deny LS rebuild workflow: face an unknown host in a
LS prompt → alt-tab to shell → `mm explain <host>` → make an informed
allow/deny decision.

Usage:
    mm explain typekit.com
    mm explain doubleclick.net
    mm explain weirdhost.example.com --json
    mm explain --refresh-data           # update DDG cache (auto on first use)

Exit codes:
    0   success
    1   lookup failed (host empty / invalid / data unavailable)
    2   DDG data unavailable AND LLM unavailable
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

_EM_HOME = Path.home() / ".empathymachine"
_DDG_DIR = _EM_HOME / "tracker-radar"
_DDG_TDS = _DDG_DIR / "tds.json"
_DDG_URL = "https://staticcdn.duckduckgo.com/trackerblocking/v5/current/extension-tds.json"
_DDG_STALE_DAYS = 30
_LLM_CACHE = _EM_HOME / "host-cache.sqlite"

_ANTHROPIC_MODEL = "claude-haiku-4-5"
_OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
_OLLAMA_MODEL = os.environ.get("EMPATHYMACHINE_OLLAMA_MODEL", "qwen3:8b")


# ─── DDG data management ─────────────────────────────────────────────────

def refresh_ddg_data(quiet: bool = False) -> None:
    _DDG_DIR.mkdir(parents=True, exist_ok=True)
    if not quiet:
        print(f"→ downloading DuckDuckGo Tracker Radar from {_DDG_URL}", file=sys.stderr)
    try:
        with urllib.request.urlopen(_DDG_URL, timeout=15) as r:
            data = r.read()
    except Exception as e:
        sys.exit(f"failed to fetch DDG data: {e}")
    _DDG_TDS.write_bytes(data)
    if not quiet:
        size_kb = len(data) // 1024
        print(f"✓ wrote {size_kb} KB → {_DDG_TDS}", file=sys.stderr)


def load_ddg() -> dict:
    """Load DDG TDS, auto-downloading on first use. Returns empty {} on failure."""
    if not _DDG_TDS.exists():
        refresh_ddg_data(quiet=False)
    age_days = (time.time() - _DDG_TDS.stat().st_mtime) / 86400
    if age_days > _DDG_STALE_DAYS:
        print(f"⚠ DDG data is {age_days:.0f} days old "
              f"(run `mm explain --refresh-data` to update)", file=sys.stderr)
    try:
        return json.loads(_DDG_TDS.read_text())
    except Exception as e:
        print(f"⚠ DDG cache corrupt ({e}); re-downloading", file=sys.stderr)
        refresh_ddg_data(quiet=True)
        return json.loads(_DDG_TDS.read_text())


# ─── lookup ──────────────────────────────────────────────────────────────

def _domain_chain(host: str) -> list[str]:
    """For 'use.typekit.net' return ['use.typekit.net', 'typekit.net']."""
    parts = host.lower().strip(".").split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]


def lookup_ddg(host: str, tds: dict) -> dict | None:
    """Return structured info from DDG TDS, or None if not present."""
    trackers = tds.get("trackers", {})
    domains_map = tds.get("domains", {})
    entities = tds.get("entities", {})

    for candidate in _domain_chain(host):
        # Strong match: tracker record
        if candidate in trackers:
            t = trackers[candidate]
            owner = t.get("owner", {})
            return {
                "source": "ddg-tracker",
                "matched": candidate,
                "owner": owner.get("displayName") or owner.get("name") or "(unknown)",
                "owner_parent": owner.get("ownedBy"),
                "categories": t.get("categories", []),
                "prevalence": t.get("prevalence"),
                "fingerprinting": t.get("fingerprinting"),  # 0-3 typically
                "cookies": t.get("cookies"),
                "ddg_default_action": t.get("default"),  # "block" or "ignore"
            }
        # Weak match: domain owned by entity
        if candidate in domains_map:
            entity_name = domains_map[candidate]
            entity = entities.get(entity_name, {})
            return {
                "source": "ddg-owner",
                "matched": candidate,
                "owner": entity.get("displayName") or entity_name,
                "owner_parent": None,
                "categories": [],
                "prevalence": entity.get("prevalence"),
                "fingerprinting": None,
                "cookies": None,
                "ddg_default_action": None,
            }
    return None


# ─── verdict heuristic ──────────────────────────────────────────────────

def derive_verdict(info: dict) -> tuple[str, str]:
    """Heuristic verdict from DDG fields. Returns (label, reasoning)."""
    src = info.get("source")
    if src == "ddg-tracker":
        if info.get("ddg_default_action") == "block":
            return ("BLOCK", "DDG default action is 'block' — pure tracker/ad infrastructure")
        cats = info.get("categories") or []
        fp = info.get("fingerprinting") or 0
        if any("Advertising" in c or "Tracking" in c for c in cats):
            return ("BLOCK", f"Classified as {', '.join(cats)}; fingerprinting score {fp}/3")
        if fp >= 2:
            return ("REVIEW", f"Medium fingerprinting ({fp}/3); inspect what calls it")
        return ("REVIEW", f"Categorized as {', '.join(cats) or 'tracker'}")
    if src == "ddg-owner":
        return ("UNKNOWN-BY-DDG", "Owned by known entity but not classified as tracker; "
                                  "likely SaaS/CDN/legitimate — judge by app context")
    return ("UNKNOWN", "Not in DDG dataset")


# ─── LLM fallback ───────────────────────────────────────────────────────

_LLM_PROMPT = """You are explaining a network hostname to a privacy-conscious user
deciding whether to allow or deny an outbound connection from one of their apps.

Hostname: {host}

Respond with ONLY a JSON object (no preamble, no markdown) with these exact keys:
{{
  "owner": "best-guess company/project that owns this domain",
  "category": "one of: CDN, Fonts, Analytics, Advertising, Telemetry, OAuth, Payments, SaaS, Streaming, Update-checker, Cloud-API, Tracker, Social-widget, Unknown",
  "purpose": "1-2 sentence plain-English description of what this host typically does",
  "breakage_impact": "what the user would observe if they DENY this host (be specific: cosmetic, login-fail, payment-fail, app-broken, etc.)",
  "verdict": "one of: SAFE-TO-ALLOW, REVIEW, BLOCK",
  "verdict_reasoning": "one sentence explaining the verdict"
}}"""


def _init_cache() -> sqlite3.Connection:
    _EM_HOME.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(_LLM_CACHE)
    conn.execute("""CREATE TABLE IF NOT EXISTS llm_cache (
        host TEXT PRIMARY KEY,
        cached_utc TEXT,
        provider TEXT,
        result_json TEXT
    )""")
    return conn


def _cache_get(host: str) -> dict | None:
    try:
        conn = _init_cache()
        row = conn.execute(
            "SELECT result_json, provider, cached_utc FROM llm_cache WHERE host = ?",
            (host,),
        ).fetchone()
        conn.close()
        if row:
            result = json.loads(row[0])
            result["_cache"] = {"provider": row[1], "cached_utc": row[2]}
            return result
    except Exception:
        pass
    return None


def _cache_put(host: str, provider: str, result: dict) -> None:
    try:
        conn = _init_cache()
        conn.execute(
            "INSERT OR REPLACE INTO llm_cache VALUES (?, ?, ?, ?)",
            (host, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
             provider, json.dumps(result)),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def call_anthropic(host: str) -> dict | None:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    payload = {
        "model": _ANTHROPIC_MODEL,
        "max_tokens": 600,
        "messages": [{"role": "user", "content": _LLM_PROMPT.format(host=host)}],
    }
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            resp = json.loads(r.read())
        text = resp["content"][0]["text"].strip()
        # Strip markdown fences if model added them
        if text.startswith("```"):
            text = text.split("```", 2)[1]
            if text.startswith("json"):
                text = text[4:]
            text = text.strip().rstrip("`").strip()
        return json.loads(text)
    except urllib.error.HTTPError as e:
        sys.stderr.write(f"anthropic error {e.code}: {e.read().decode()[:200]}\n")
    except Exception as e:
        sys.stderr.write(f"anthropic call failed: {e}\n")
    return None


def call_ollama(host: str) -> dict | None:
    payload = {
        "model": _OLLAMA_MODEL,
        "prompt": _LLM_PROMPT.format(host=host),
        "stream": False,
        "format": "json",
    }
    req = urllib.request.Request(
        _OLLAMA_URL,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            resp = json.loads(r.read())
        return json.loads(resp.get("response", "{}"))
    except Exception:
        return None


def llm_fallback(host: str) -> dict | None:
    cached = _cache_get(host)
    if cached:
        return cached
    # Try Anthropic first (fast, reliable), then Ollama (offline-capable)
    for provider, fn in (("anthropic", call_anthropic), ("ollama", call_ollama)):
        result = fn(host)
        if result:
            _cache_put(host, provider, result)
            result["_cache"] = {"provider": provider, "cached_utc": "fresh"}
            return result
    return None


# ─── output formatting ──────────────────────────────────────────────────

def render_ddg(host: str, info: dict) -> str:
    lines = [f"{host}"]
    matched = info.get("matched")
    if matched and matched != host:
        lines.append(f"  Matched parent domain:  {matched}")
    lines.append(f"  Owner:                  {info.get('owner')}"
                 + (f"  (under {info['owner_parent']})" if info.get("owner_parent") else ""))
    if info.get("categories"):
        lines.append(f"  DDG categories:         {', '.join(info['categories'])}")
    if info.get("prevalence") is not None:
        # DDG quirk: tracker prevalence is 0..1 (fraction), entity prevalence
        # is 0..100 (already a percent). Normalize for display.
        raw = info["prevalence"]
        pct = raw * 100 if info.get("source") == "ddg-tracker" else raw
        lines.append(f"  Prevalence:             ~{pct:.1f}% of tracked sites")
    if info.get("fingerprinting") is not None:
        lines.append(f"  Fingerprinting score:   {info['fingerprinting']}/3  "
                     f"(0=none, 3=high)")
    if info.get("cookies") is not None:
        lines.append(f"  Cookies (proportion):   {info['cookies']:.2f}")
    if info.get("ddg_default_action"):
        lines.append(f"  DDG default action:     {info['ddg_default_action']}")
    verdict, reason = derive_verdict(info)
    lines.append(f"  Verdict:                {verdict}")
    lines.append(f"    Reasoning:            {reason}")
    lines.append(f"  Source:                 DuckDuckGo Tracker Radar")
    return "\n".join(lines)


def render_llm(host: str, info: dict) -> str:
    lines = [f"{host}"]
    lines.append(f"  Owner:                  {info.get('owner', '(unknown)')}")
    lines.append(f"  Category:               {info.get('category', '(unknown)')}")
    lines.append(f"  Purpose:                {info.get('purpose', '(unknown)')}")
    lines.append(f"  Breakage if denied:     {info.get('breakage_impact', '(unknown)')}")
    lines.append(f"  Verdict:                {info.get('verdict', 'REVIEW')}")
    lines.append(f"    Reasoning:            {info.get('verdict_reasoning', '(unknown)')}")
    cache = info.get("_cache") or {}
    lines.append(f"  Source:                 LLM ({cache.get('provider', '?')})"
                 + (f"  cached={cache.get('cached_utc')}" if cache.get('cached_utc') != "fresh" else ""))
    return "\n".join(lines)


# ─── main ───────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("host", nargs="?", help="hostname to explain")
    p.add_argument("--json", action="store_true", help="emit JSON instead of pretty text")
    p.add_argument("--refresh-data", action="store_true",
                   help="re-download DDG Tracker Radar dataset and exit")
    p.add_argument("--no-llm", action="store_true",
                   help="skip LLM fallback even if available")
    args = p.parse_args(argv)

    if args.refresh_data:
        refresh_ddg_data(quiet=False)
        return 0
    if not args.host:
        p.error("host argument required (or use --refresh-data)")

    host = args.host.strip().lower()
    if not host or " " in host or "/" in host:
        sys.exit(f"invalid hostname: {args.host!r}")

    tds = load_ddg()

    ddg = lookup_ddg(host, tds)
    if ddg:
        if args.json:
            verdict, reason = derive_verdict(ddg)
            ddg["verdict"] = verdict
            ddg["verdict_reasoning"] = reason
            print(json.dumps(ddg, indent=2))
        else:
            print(render_ddg(host, ddg))
        return 0

    if args.no_llm:
        msg = f"{host}: not found in DDG Tracker Radar (LLM fallback skipped)"
        if args.json:
            print(json.dumps({"host": host, "source": None, "error": "not-found"}, indent=2))
        else:
            print(msg)
        return 1

    llm = llm_fallback(host)
    if llm:
        if args.json:
            llm["host"] = host
            llm["source"] = "llm"
            print(json.dumps(llm, indent=2))
        else:
            print(render_llm(host, llm))
        return 0

    sys.stderr.write(
        f"{host}: not in DDG and no LLM available\n"
        f"  set ANTHROPIC_API_KEY or run a local Ollama with {_OLLAMA_MODEL} pulled\n"
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
