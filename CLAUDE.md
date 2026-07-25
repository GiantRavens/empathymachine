# empathymachine — agent orientation

**Read [`DESIGN.md`](DESIGN.md) first.** That's the orienting north-star
for the project — the architectural thesis, the OODA loop applied to
network policy, the dignity safeguards, the roadmap. Code ships against
that vision.

Then read [`README.md`](README.md) for the user-facing reference.

This file is the fast cold-start: load-bearing facts an AI agent needs
to use EmpathyMachine correctly in a fresh session.

## What it is

Rust HTTP(S) MITM proxy + DNS sinkhole. Local-only by default
(`127.0.0.1:8080` proxy, `:8081` admin HTTP/dashboard, `:8053` DNS).
Blocks via hosts-format lists. Rewrites via lol_html streaming HTML
transforms (remove selectors, CSS injection, text replace). Captain uses
it as their daily ad/tracker blocker on Linux + macOS.

## File layout (orient here first)

```
empathymachine/
├── empathymachine          # bash launcher — what 'mm' points at
├── target/release/empathymachine   # the Rust binary the launcher prefers
├── src/                    # Rust source (~3,300 LOC, 10 files)
│   ├── proxy.rs            # CONNECT + MITM (980 LOC)
│   ├── rewriter.rs         # lol_html element/CSS/text rewrites (335 LOC)
│   ├── admin.rs            # HTTP API at :8081 (628 LOC)
│   ├── dns.rs              # trust-dns sinkhole at :8053
│   ├── blocklist.rs / blocklist_fetcher.rs   # hosts-format parsing + refresh
│   └── ca.rs / config.rs / main.rs / lib.rs
├── config.yaml             # user config (gitignored; synced via Syncthing)
├── certs/root_ca.pem|key   # auto-generated CA (gitignored)
├── blocklists/             # hosts files; custom.txt is user-managed
├── scripts/                # install_systemd.sh, install_launchd.sh, install_tray.sh,
│                           # install_cert.sh, edit_config_bypass.py, .plist templates,
│                           # em-proxy-reapply (Mac netwatch helper)
├── mcp/mcp_server.py       # MCP server (15 tools)
├── gui/tray.py             # cross-platform pystray menu-bar app
├── state/jobs.jsonl        # (none here — empathymachine doesn't have one; this is the kf pattern)
└── tests/                  # 28 Rust tests across cli_wrapper, dns, blocking, metrics, etc.
```

Outside the repo, EmpathyMachine writes to:

- `~/.empathymachine/` — TCC-safe helper dir. Holds `em-proxy-reapply`
  (Mac netwatch script), `proxy-desired.txt` (state file), `tray.py`
  copy + `.venv/`. **All Mac LaunchAgent ProgramArguments point HERE, not
  at the project dir under ~/Desktop.** This is load-bearing per the
  TCC memory.
- `~/Library/LaunchAgents/com.giantravens.empathymachine{,-netwatch,-tray}.plist`
- `~/.config/systemd/user/empathymachine.service` (Linux)
- `~/.config/autostart/empathymachine-tray.desktop` (Linux)

## Two operational gotchas to memorize

1. **macOS Gatekeeper prompts on first launchd spawn of the binary.** The
   user must click "Allow Anyway" in Privacy & Security one time. See
   [[feedback_mac_gatekeeper_launchd]] in user memory.

2. **macOS TCC blocks LaunchAgents from exec'ing shell scripts under
   ~/Desktop.** All LaunchAgent ProgramArguments must point at files
   under `~/.empathymachine/` or another dot-prefixed user dir. See
   [[feedback_mac_tcc_launchagent_desktop]] in user memory.

   Practical consequence: when adding a new LaunchAgent that runs a
   helper script, INSTALL the script into `~/.empathymachine/` via the
   installer (don't have the plist reference the source-of-truth under
   `~/Desktop/notebook/code/empathymachine/scripts/`).

## Launcher subcommand surface

`./empathymachine <cmd>` (alias `mm`):

| Lifecycle | Cert | Proxy | Bypass |
|---|---|---|---|
| `status` | `install-cert` | `proxy-on` | `bypass <host>` |
| `stop` | `uninstall-cert` | `proxy-off` | `unbypass <host>` |
| `restart` | | `proxy-status` | `bypass-list` |
| `logs` | | `proxy-reapply` (used by netwatch on Mac) | |
| `start` (foreground) | | | |
| `refresh-blocklists` | | | |
| `dump-ca` | | | |
| `selftest` | | | |

The launcher prefers `target/release/empathymachine` when present, falls
back to `cargo run` otherwise. Honors `EMPATHYMACHINE_CARGO_CMD` for test
stubbing (`tests/cli_wrapper.rs`).

## Config edit pattern

Don't blindly rewrite `config.yaml` — captain has comments and a curated
text-substitution list (Trump → Orange Shitstain, etc.) in it. To edit
the bypass list, use `scripts/edit_config_bypass.py` (line-level insert,
preserves all surrounding formatting). For blocklist edits, the MCP
server's `add_block`/`remove_block` write only to `blocklists/custom.txt`
(not config.yaml). For rewrite rules, edit by hand and `mm restart`.

## Sync model

`config.yaml`, `blocklists/`, `certs/`, and the whole notebook tree sync
between Mac + Linux via Syncthing. The single CA is intentionally shared
across the captain's two devices. Build artifacts (`target/`) and venvs
(`.venv-mcp/`, `~/.empathymachine/.venv/`) are host-local — not synced,
must be rebuilt per machine.

Tests: `cargo test --release` → 28 pass + 1 pre-existing `metrics::*` fail
(unrelated; pre-dates the 2026-05-23 retool — captain hasn't prioritized).

## When extending

- **New launcher subcommand:** add `cmd_<name>()`, register in the
  `case "${COMMAND}"` dispatch at the bottom. If it needs Mac TCC
  awareness (anything launchd will invoke), put the actual work in
  `~/.empathymachine/` and have the installer copy it there.
- **New MCP tool:** decorate with `@mcp.tool()` in `mcp/mcp_server.py`.
  Read tools should `_fetch_json("/api/...")`; write tools usually shell
  to the launcher via `_run_launcher()`.
- **New rewriter behavior:** edit `src/rewriter.rs` (it's the lol_html
  layer). Beware the early-bail on non-identity Content-Encoding — the
  proxy strips Accept-Encoding on outbound, so most responses arrive
  identity already, but the safety check is there.
- **New tray menu item:** edit `gui/tray.py` `build_menu()`. Remember
  the script also has to be copied to `~/.empathymachine/tray.py` by
  the installer; `bash scripts/install_tray.sh` does this idempotently.

## Host explainer

`scripts/explain_host.py` (and `mm explain <host>` / MCP `explain_host`).
Two-tier lookup: DuckDuckGo Tracker Radar (offline, ~1.5 MB cached at
`~/.empathymachine/tracker-radar/tds.json`, auto-refreshed if >30 days)
+ LLM fallback (Anthropic API or local Ollama). LLM results cached in
`~/.empathymachine/host-cache.sqlite`.

Key implementation notes:
- DDG `trackers` map: fraction-prevalence (0..1, multiply by 100).
- DDG `entities` map: percent-prevalence (already 0..100, don't multiply).
  Easy to confuse — `render_ddg()` handles both via `info["source"]`.
- Suffix matching: `_domain_chain('use.typekit.net')` → `['use.typekit.net',
  'typekit.net']` so subdomains find parent classifications.
- LLM JSON output: parse with markdown-fence stripping; some models wrap.

## Little Snitch importer

`scripts/import_littlesnitch.py` (and `mm import-littlesnitch <export>`)
ingests an LS JSON export into `blocklists/littlesnitch_imports.txt`.
Auto-registers the file in `config.yaml`'s `blocklists:` list on first
run. Idempotent via `state/last_ls_import.json`. The parser is tolerant
of LS 4.x and 5.x field name variants (`remote-host` vs `remote-hosts`
vs `remoteHost` vs nested `remote: {host: ...}`; `action` vs `verdict`;
`deny`/`block` synonyms). Per-process rules + IP-only rules +
"any-domain" wildcards are intentionally skipped.

To debug an unrecognized LS export shape: `mm import-littlesnitch
<export> --inspect`. Sample fixture covering the supported variants at
`tests/fixtures/littlesnitch_export_sample.json`.

## Project memory

User memory carries [[project_empathymachine]] with the full retool log
and [[feedback_mac_gatekeeper_launchd]] / [[feedback_mac_tcc_launchagent_desktop]]
for the two known macOS deployment gotchas. Update both when you ship
material changes to the install model or daemon supervision.
