# EmpathyMachine

EmpathyMachine is a Rust-based HTTP/HTTPS proxy designed to block trackers and ads while letting you inspect or intercept TLS traffic when you trust the generated root certificate. It succeeds the earlier Python prototype called middleman and focuses on performance, modern TLS support, and flexible blocklist management.

Unlike DNS-only solutions such as Pi-hole or AdGuard Home, EmpathyMachine operates at the HTTP layer as well, allowing on-the-fly content rewrites, TLS interception for deeper inspection, and per-request decisions informed by both DNS and application data. It coexists with traditional network blockers like the excellent Little Snitch. 

Use it to streamline and quiet your personal web experience by removing or rewriting entire web page sections or common patterns on the fly, even replace mindless jargon like "utilize" with "use". 

## Responsible Use

Use **EmpathyMachine** to understand the scope and impact of aggressive ad and tracking tech as you browse, but "with great power comes great responsibility": only intercept traffic you own or have permission to inspect, and stay within local laws and site terms of service.

## Key Features

- **Hosts-format blocklists** – Load local files or fetch remote lists (Steven Black, OISD, etc.) to deny matching domains or URL path fragments.
- **HTTPS interception with rcgen 0.14 + rustls 0.21** – Generates and persists a self-signed CA, automatically issues leaf certificates per host, and performs MITM for inspection.
- **Configurable bypass allowlist** – Skip interception for pinned or unsupported services by listing exact domains or wildcard suffixes (for example, `gateway.icloud.com`).
- **DNS sinkhole with trust-dns** – Runs a local resolver that answers blocked domains with `0.0.0.0`/`::` (or NXDOMAIN) and forwards everything else to secure upstreams (DoT/DoH/DNSSEC).
- **CLI utilities & wrapper** – The `./empathymachine` launcher wraps `cargo run` and exposes shortcuts like `start`, `dump-ca`, and `refresh-blocklists`. Under the hood the binary still accepts flags such as `--dump-ca` to print the root certificate PEM or `--refresh-blocklists` to fetch remote sources and exit.
- **Rich logging** – Uses `tracing` to show blocked requests, TLS interception outcomes, and blocklist refresh status.

## Requirements

- Rust toolchain (Rust 1.75+ recommended) and Cargo
- macOS/Linux environment (tested primarily on macOS)
- Network clients configured to use the proxy (`127.0.0.1:8080` by default)

## Getting Started

1. Clone and enter the project:

    ```bash
    git clone https://github.com/GiantRavens/empathymachine.git
    cd empathymachine
    cp config.sample.yaml config.yaml      # edit as needed
    ```

2. Build the release binary (one time; ~1–3 min). Use `mm build`
   instead of raw `cargo` so the macOS ad-hoc codesign happens
   automatically — without it Little Snitch will prompt per-destination
   for every outbound connection from the binary:

    ```bash
    ./empathymachine build         # cargo build --release + codesign on Mac
    ```

    On Linux the codesign step is a silent no-op. Re-run `mm build`
    after any source change.

3. Install as a supervised service for spin-up/down ergonomics:

    **Linux** (systemd `--user`):

    ```bash
    bash scripts/install_systemd.sh --enable    # installs, daemon-reloads, starts, autostarts on login
    ```

    Use `loginctl enable-linger $USER` if you also want it running while logged out.

    **macOS** (launchd LaunchAgent + network-change watcher):

    ```bash
    bash scripts/install_launchd.sh             # installs main service + netwatch agent, both load+start
    ```

    Installs two agents: the main service (`com.giantravens.empathymachine`)
    and a netwatch agent (`com.giantravens.empathymachine-netwatch`) that
    re-applies your desired proxy state whenever the active network service
    changes (Wi-Fi flap, Ethernet plug/unplug). Both autostart at login.

    On first launch macOS Gatekeeper will prompt to allow the binary —
    click **Allow Anyway** in System Settings → Privacy & Security. The
    netwatch agent works without further prompts since it runs a helper
    script installed under `~/.empathymachine/`.

    Both `install_launchd.sh` and `mm build` apply an **ad-hoc code
    signature** to the release binary (`codesign --sign - --force`).
    Without this, Little Snitch refuses to apply broad "any process"
    rules to unsigned binaries and prompts per-destination. Either
    command keeps the signature current — but **always rebuild with
    `mm build`, not raw `cargo build --release`**, so the signature
    can't get stale.

4. Trust the auto-generated CA in your OS trust store + Firefox NSS:

    ```bash
    ./empathymachine install-cert
    ```

    Linux installs to `/usr/local/share/ca-certificates/` (needs sudo).
    macOS installs to `/Library/Keychains/System.keychain` (prompts for password).
    Firefox profiles are detected and updated automatically when `certutil` is
    present (`sudo apt install libnss3-tools` on Debian/Ubuntu;
    `brew install nss` on macOS).

5. (Optional but recommended) Install the menu-bar tray app:

    ```bash
    bash scripts/install_tray.sh                # creates ~/.empathymachine/.venv, registers autostart
    ```

    Adds an **em** icon to the macOS menu bar (or Linux GNOME/KDE system
    tray) with proxy toggle, service controls, and a link to the dashboard.
    Strike-through means the service is stopped. Linux GNOME stock users
    also need `sudo apt install gnome-shell-extension-appindicator` and to
    enable it via the Extensions app.

6. Point your browser to `127.0.0.1:8080`. On Linux Firefox additionally
   needs Preferences → Network Settings → **Use system proxy settings**.

## Day-to-day operation

```bash
./empathymachine status               # state + admin /api/status + /api/metrics
./empathymachine stop                 # systemd stop / launchctl unload
./empathymachine restart              # systemd restart / launchctl kickstart -k
./empathymachine logs                 # journal (Linux) or ~/Library/Logs (Mac)
./empathymachine refresh-blocklists   # fetch remote lists

./empathymachine install-cert / uninstall-cert

./empathymachine proxy-on             # point the system proxy at 127.0.0.1:8080
./empathymachine proxy-off            # clear it
./empathymachine proxy-status         # show current OS proxy setting
./empathymachine proxy-reapply        # re-apply desired state (used by netwatch on Mac)

./empathymachine bypass <host>        # add host to tls.bypass_hosts and restart
./empathymachine unbypass <host>      # remove host from bypass list and restart
./empathymachine bypass-list          # print every host in the bypass list
```

Shell alias suggestion (in `code/dotfiles/common/.zshrc`):

```bash
alias mm='~/Desktop/notebook/code/empathymachine/empathymachine'
# then: mm status, mm bypass site.com, mm proxy-off, mm restart, etc.
```

### Spinning the system proxy on/off

`proxy-on` and `proxy-off` wrap the OS-native one-liners so you don't have
to navigate System Settings (macOS) or GNOME Settings → Network → Proxy
(Linux). Auto-detects:

- **macOS:** the active network service (Wi-Fi, Ethernet, …) via
  `networksetup -listnetworkserviceorder`. Override with
  `EMPATHYMACHINE_MAC_SERVICE='Wi-Fi'`.
- **Linux GNOME family** (incl. Cinnamon, Pantheon, MATE, Budgie): uses
  `gsettings` against `org.gnome.system.proxy`. Probes via `gsettings`
  even when `XDG_CURRENT_DESKTOP` isn't set (tmux/SSH).
- **Linux KDE/Plasma:** `kwriteconfig5` or `kwriteconfig6` against
  `kioslaverc`.

Some apps cache the proxy at startup — restart browsers if traffic doesn't
appear to route. The proxy service keeps running across `proxy-off`; only
the system's pointer to it is cleared.

### Bypass a site that breaks under MITM

Cert-pinning sites (some banking, work SSO, anti-bot-protected services)
won't accept the EmpathyMachine MITM cert. Add them to the bypass list:

```bash
mm bypass mybank.example.com         # tunneled through unchanged, restart triggered
mm bypass-list                       # see what's currently bypassed
mm unbypass mybank.example.com       # re-enable MITM for it
```

The bypass list is edited in place in `config.yaml` under `tls.bypass_hosts`
with all comments/formatting preserved.

### Network-change auto-reapply (macOS)

`scripts/install_launchd.sh` installs a second LaunchAgent that watches
`/Library/Preferences/SystemConfiguration/*.plist` and fires
`~/.empathymachine/em-proxy-reapply` whenever the active network service
changes. So when you unplug an Ethernet dongle and Wi-Fi takes over, or
roam between Wi-Fi networks, the proxy setting follows you automatically.
Desired state lives in `~/.empathymachine/proxy-desired.txt` (written by
`mm proxy-on` / `mm proxy-off`). The reapply script is self-contained and
only touches `networksetup` — no project files involved, so it works under
launchd's TCC sandbox.

Linux doesn't need this — `gsettings` proxy settings are user-global and
persist across network changes automatically.

## Policy brain (`mm policy`)

`policy.yaml` is the source of truth for the captain's privacy/control
decisions, with reasoning trace. Every entry captures *why* a decision
was made — captured conversation, trade-off considered, priority being
honored. The architecture is documented in [`DESIGN.md`](DESIGN.md);
this section is the operational reference.

```bash
mm policy show                     # summary of every entry
mm policy show block_quic          # full reasoning trace for one decision
mm policy set <name> <value> --note "captured reasoning"
                                   # create/update (note REQUIRED)
mm policy compile                  # dry-run: what would config.yaml change
mm policy compile --apply --restart
                                   # propagate policy.yaml → config.yaml + restart
mm policy why <name>               # show reasoning trace
mm policy review                   # entries past their review_by date
```

The first shipped entry is `block_quic` (Section 4 of DESIGN.md). On
`policy compile --apply`, EM strips `Alt-Svc` response headers and
emits `Alt-Svc: clear` (RFC 7838 §4) to invalidate cached entries.
Browsers fall back to HTTPS/TCP and EM keeps full visibility.

policy.yaml supports two sections:

- `network_policy` — protocol/transport toggles (currently: `block_quic`).
  Compiles to runtime flags in `config.yaml`'s `network_policy` block.
- `presentation_policy` — per-site visual + content rules with structured
  `apply:` blocks (`remove_selectors`, `css_hide_selectors`, `block_hosts`).
  Compiles to **fenced managed regions** in `config.yaml`'s
  `rewrites.remove` / `rewrites.css` (markers: `# === BEGIN/END
  policy.yaml managed ===`) plus a managed `blocklists/policy_imports.txt`
  file. Idempotent — re-running compile cleanly updates the managed
  regions without disturbing captain's hand-written entries.

  First shipped entry: `block_anti_adblock_walls` — strips Admiral's
  inline loader script + CSS-hides the modal + blocks Admiral's cloaked
  CDN domains. Effective on Hollywood Reporter, Variety, Rolling Stone,
  Deadline, IndieWire, and other PMC properties.

MCP tools `policy_show`, `policy_set`, `policy_compile`, `policy_why`,
`policy_review` expose the same surface to any Claude session.

## Little Snitch rule subscription (closes the EM → LS loop)

`http://127.0.0.1:8081/api/lsrules` serves a Little Snitch Subscribed
Rule Group generated from your current policy.yaml. Subscribe once in
LS, and every `mm policy` decision (or LLM-driven `policy_set`
conversation) auto-propagates to LS on its next refresh.

**One-time setup in Little Snitch:**

1. LS app → **Rules** sidebar
2. **+** button (bottom-left) → **Add Subscribed Rule Group…**
3. URL: `http://127.0.0.1:8081/api/lsrules`
4. Update interval: every 1 hour (or your preference)
5. Save

LS will fetch the URL, parse the JSON, and apply the rules. From then
on, when you `mm policy compile --apply --restart`, LS pulls fresh
rules within the refresh interval (force immediate refresh via LS UI:
right-click the subscribed group → **Update Now**).

Currently published rules:
- `block_quic: true` in policy.yaml → outbound UDP/443 deny rule
  (belt-and-suspenders enforcement at the kernel layer, alongside the
  EM rewriter's Alt-Svc strip)

As more policy decisions land in policy.yaml, more rules appear at the
endpoint without any captain action. The architecture intent is in
[`DESIGN.md`](DESIGN.md) §2: EM as policy brain, LS as one of many
enforcement substrates.

## Host explainer (`mm explain <host>`)

Look up a hostname's owner, tracker classification, and what would
break if you deny it. Two-tier lookup:

1. **DuckDuckGo Tracker Radar** (offline, auto-downloads on first use to
   `~/.empathymachine/tracker-radar/tds.json`) — covers ~1k known
   third-party trackers + ~5.5k domain→owner mappings with prevalence,
   fingerprinting score, cookie behavior, and DDG's own block/ignore
   recommendation.
2. **LLM fallback** for hosts DDG doesn't classify — prefers Anthropic
   Claude API (set `ANTHROPIC_API_KEY`), falls back to local Ollama
   (`qwen3:8b` by default; override with `EMPATHYMACHINE_OLLAMA_MODEL`).
   Results cached in `~/.empathymachine/host-cache.sqlite` — repeat
   lookups are free.

```bash
mm explain doubleclick.net      # full tracker classification + BLOCK verdict
mm explain typekit.com          # owner-only (Adobe) + REVIEW verdict
mm explain weirdhost.example.com  # falls through to LLM, returns Owner/Purpose/Verdict
mm explain --refresh-data       # update DDG dataset (auto-refreshed if >30 days)
```

Pairs naturally with the Little Snitch Alert+Deny rebuild workflow: when
LS prompts about an unknown host, `mm explain` (or "claude, what is X"
via MCP) gives you the context needed to make an informed decision.

Also reachable as MCP tool `explain_host(host)` for use from any Claude
Code session.

## Little Snitch integration (macOS — recommended)

If you run Little Snitch on Mac, EmpathyMachine complements rather than
competes. LS gives you per-process firewall decisions at the kernel
layer; EM enforces hostname-pattern decisions across DNS + HTTP
everywhere (Linux, future Pi-as-LAN-DNS, every non-proxy-aware app).
Two tools, two layers. The cool bit: **LS deny-rules you've curated
over time become EM blocklist entries that work everywhere**, not just
on the one Mac LS runs on.

### Workflow

```bash
# 1. In Little Snitch app: File → Export Rules… → choose JSON → save the .json
mm import-littlesnitch ~/Downloads/ls-rules.json              # dry-run, shows what'd come across
mm import-littlesnitch ~/Downloads/ls-rules.json --apply      # write blocklist + register in config
mm restart                                                     # take effect
```

The importer:
- Reads any LS 4.x or 5.x JSON export shape
- Splits into deny-any-process (→ blocklist) and allow-any-process
  (→ proposed `tls.bypass_hosts` additions, shown but not auto-applied)
- Skips per-process rules (EM has no process awareness — can't tell
  "Spotify only" from a hostname-level vantage point)
- Skips IP-only rules, wildcards, and "any-domain" catch-alls
- Writes to `blocklists/littlesnitch_imports.txt` (separate file so you
  always see what came from where)
- Auto-registers that file in `config.yaml`'s `blocklists:` list on
  first run
- Idempotent — re-runs show deltas via `state/last_ls_import.json`

### Captain's clean-slate workflow (advanced)

Best long-term setup: in Little Snitch, set Profile mode to **Alert &
Deny** so every new outbound connection prompts you. Over a few days,
your accumulated decisions build a high-quality rule set scoped to your
actual usage. Periodically run `mm import-littlesnitch <export>
--apply` to promote those decisions into EM's blocklist for cross-platform
and LAN-wide enforcement. Seed first with always-allow rules for Apple
system services (mDNSResponder, syncdefaultsd, calaccessd, Calendar,
Mail, Time Machine, Software Update, configd) to avoid spending the
first hour clicking through system-service prompts.

## Menu-bar / system-tray app

`bash scripts/install_tray.sh` installs a small cross-platform tray app
(Python + pystray) to `~/.empathymachine/tray.py`. The icon is a lowercase
**em**, monochrome (adapts to dark/light menubar), with a diagonal strike
when the service is stopped.

Menu items:
- Header showing version + uptime + live request/block counters
- **Proxy: System Routing** — checkmark toggles proxy on/off
- **Start / Stop / Restart Service** — calls `launchctl` (Mac) or `systemctl --user` (Linux)
- **Open Dashboard…** — opens `http://127.0.0.1:8081` in default browser
- **Quit Tray** — exits the tray (service keeps running)

Polls `/api/status` + `/api/metrics` every 5 seconds and redraws when state
changes. Lives in `~/.empathymachine/` (TCC-safe) with its own venv at
`~/.empathymachine/.venv/`. On Mac, autostart is via a launchd LaunchAgent
(`com.giantravens.empathymachine-tray.plist`). On Linux, autostart is via a
`.desktop` file in `~/.config/autostart/`.

## LLM control (MCP server)

The proxy is addressable by any MCP-speaking LLM via `mcp/mcp_server.py`.
Tools exposed:

- **Read:** `status`, `metrics`, `recent_blocks`, `list_custom_blocks`, `list_bypass_hosts`, `system_proxy_status`
- **Blocklist write:** `add_block`, `remove_block`, `refresh_blocklists`
- **Bypass write:** `bypass_host`, `unbypass_host`
- **Service control:** `start_proxy`, `stop_proxy`, `restart_proxy`
- **System proxy:** `system_proxy_on`, `system_proxy_off`
- **Imports:** `import_littlesnitch`
- **Knowledge:** `explain_host`
- **Policy:** `policy_show`, `policy_set`, `policy_compile`, `policy_why`, `policy_review`

So you can drive the whole tool from a Claude Code session: "claude, block
doubleclick.net", "claude, what has EmpathyMachine blocked recently?",
"claude, bypass mybank.example.com", "claude, turn off the system proxy".

Register at user scope in `~/.claude.json` under `mcpServers`:

```json
"empathymachine": {
  "type": "stdio",
  "command": "/home/skip/Desktop/notebook/code/empathymachine/.venv-mcp/bin/python",
  "args": ["/home/skip/Desktop/notebook/code/empathymachine/mcp/mcp_server.py"]
}
```

Setup once:

```bash
uv venv .venv-mcp --python python3
uv pip install --python .venv-mcp/bin/python mcp
```

Write tools (`add_block`, `remove_block`) edit `blocklists/custom.txt` and
restart the proxy so the new rule takes effect. Restart is ~1 s under systemd
with the release binary; a future hot-reload (SIGHUP handler) will eliminate
even that pause.

## Configuration

EmpathyMachine reads `config.yaml` (use `config.sample.yaml` as a template). Key sections:

```yaml
bind_addr: "127.0.0.1:8080" # proxy listen address (change to 0.0.0.0:8080 to serve other devices)
blocklists: []              # local hosts-format files to load
sources:                    # optional remote blocklist downloads
  - url: "https://example.com/hosts"
    destination: "blocklists/example-hosts.txt"

tls:
  enable_intercept: true    # turn HTTPS MITM on/off
  ca_dir: certs             # directory for root CA and keys
  upstream_insecure: false  # allow invalid upstream certs when true
  bypass_hosts:             # domains to tunnel without interception
  #  - "gateway.icloud.com"

dns:
  enable: true                # start the embedded trust-dns sinkhole
  bind_addr: "127.0.0.1:8053" # UDP/TCP listener for DNS clients (using 0.0.0.0:8053 for LAN clients)
  upstreams:                  # DoT/DoH/UDP/TCP resolvers EmpathyMachine forwards to
    - address: "1.1.1.1:853"  # example using Cloudflare's DNS service 
      transport: tls
      dns_name: "cloudflare-dns.com"

# define blocklist sources url and destination
sources:
  - url: "https://raw.githubusercontent.com/StevenBlack/hosts/refs/heads/master/hosts"
    destination: "blocklists/stevenblack_hosts.txt"

# define global rewrites
rewrites:
  remove:
    - "iframe"
  replace:
    - find: "utilize"
      replace: "use"
  css:
    - ".annoying-popup { display: none !important; }"
  
  # define per-host rewrites
  hosts:
    example.com:
      remove:
        - "#TerribleWidget"
      css:
        - "#AnnoyingWidget { display: none !important; }"
```

- **`blocklists`** – Paths to hosts-format files that contain either domains or path fragments (leading `/`); comments use `#`. A starter template lives at `blocklists/custom.sample.txt`—copy it to `blocklists/custom.txt` for local overrides.
- **`sources`** – Remote lists EmpathyMachine can download via `cargo run -- --refresh-blocklists`.
- **`tls.enable_intercept`** – Disabling it turns the proxy into a simple TCP tunnel for HTTPS and disables CA material generation.
- **`tls.bypass_hosts`** – Entries are case-insensitive; if an entry starts with `*.` it applies to any subdomain. Ports are ignored during matching, so a single entry covers all ports for that host.
- **`bind_addr` / `dns.bind_addr`** – `127.0.0.1` keeps EmpathyMachine local-only; `0.0.0.0` exposes the proxy/DNS sinkhole to other hosts on your LAN (ensure your firewall allows inbound traffic and clients install the CA).

Environment variables:

- `EMPATHYMACHINE_CONFIG` – Path to an alternative configuration file.
- `EMPATHYMACHINE_BIND` – Override listen address (e.g. `0.0.0.0:8080`).

Remember to restart the proxy after editing `config.yaml` for changes to take effect.

### Rewrite Actions Explained

EmpathyMachine applies rewrite rules in three passes whenever an intercepted response is matched in HTML:

1. **remove** – Treat entries as CSS selectors; any matching elements are stripped from the document.@src/rewriter.rs#137-155@src/rewriter.rs#194-203
2. **replace** – Perform plain-text substitutions across the HTML body using the configured `find` → `replace` pairs.@src/rewriter.rs#137-161@src/rewriter.rs#205-212
3. **css** – Inject a `<style data-empathymachine>…</style>` block containing the listed rules so you can hide or restyle content non-destructively.@src/rewriter.rs#163-177@src/rewriter.rs#237-267

Global rules run for *every* host, while host-specific sections under `rewrites.hosts` are merged in before the passes above, allowing per-domain tailoring on top of site-wide defaults.@src/rewriter.rs#194-224

## DNS Sinkhole Usage

1. Enable the DNS section in `config.yaml` (see above). By default the sample configuration binds to `127.0.0.1:8053` and forwards to Cloudflare DoT with DNSSEC validation. Port :8053 seems to play nicely with local services.
2. Start EmpathyMachine (`empathymachine start`). You should see a log line similar to `dns sinkhole listening bind=127.0.0.1:8053`.
3. Verify blocking with `dig` (replace the domain with one present in your blocklist):

   ```bash
   dig @127.0.0.1 -p 8053 adsandtrackingareawesome.com A
   dig @127.0.0.1 -p 8053 adsandtrackingareawesome.com AAAA
   ```

   Blocked domains efficiently return `0.0.0.0` for A records, `::` for AAAA, and NXDOMAIN for other types. Allowed domains are forwarded to the configured upstreams.
4. Point client devices to EmpathyMachine for DNS. On macOS you can configure Wi‑Fi → DNS via **System Settings → Wi-Fi → Details → DNS**; keep a fallback resolver beneath `127.0.0.1` if you like.

   ```text
   Server: 127.0.0.1
   Server: 1.1.1.1
   ```

With DNS routed through EmpathyMachine, all subdomains of a listed host are also sinkholed (e.g. a `adsandtrackingareawesome.com` entry covers `www.adsandtrackingareawesome.com`, `evenmoreads.adsandtrackingareawesome.com`, etc.).

## Operational Tips

- **Observing logs** – `tracing` emits INFO for blocked requests and WARN for TLS or HTTP issues (e.g., clients that reject MITM or non-HTTP protocols like `mtalk.google.com`). If a service pins certificates or uses HTTP/2 only, add it to `tls.bypass_hosts`.
- **Blocklist refresh** – Run `./empathymachine refresh-blocklists`; EmpathyMachine downloads configured sources and exits. Alternatively, pass `--update-lists` when running `./empathymachine start` to refresh lists before launching the proxy.
- **Testing** – Execute `cargo test` to run unit and integration tests. Current suites cover blocklist behavior and HTTP pass-through scenarios.
- **Certificates** – Root CA and keys live under the `ca_dir` (default `certs`). Deleting that directory will cause a new CA to be generated on next startup. See [docs/cert-import.md](docs/cert-import.md) for platform-specific trust-store instructions.

## Current Limitations

- HTTPS MITM only supports HTTP/1.1 downstream. HTTP/2-capable clients may fallback or abort; add such domains to the bypass list for now.
- No UI yet for managing blocklists or bypass entries—everything is file-based.
- Services that pin certificates (e.g., some ChatGPT or Microsoft telemetry endpoints) must be bypassed to avoid warnings.

## Files & install locations

EmpathyMachine touches several places outside the project directory:

| Path | Purpose | OS |
|---|---|---|
| `~/.empathymachine/` | TCC-safe helper home: `em-proxy-reapply` script, `proxy-desired.txt` state, `tray.py` + `.venv/` | both |
| `~/.config/systemd/user/empathymachine.service` | Main service unit | Linux |
| `~/.config/autostart/empathymachine-tray.desktop` | Tray autostart entry | Linux |
| `~/Library/LaunchAgents/com.giantravens.empathymachine.plist` | Main service agent | macOS |
| `~/Library/LaunchAgents/com.giantravens.empathymachine-netwatch.plist` | Network-change watcher → `em-proxy-reapply` | macOS |
| `~/Library/LaunchAgents/com.giantravens.empathymachine-tray.plist` | Tray autostart agent | macOS |
| `~/Library/Logs/empathymachine*.log` | Service / netwatch / tray logs | macOS |
| `/usr/local/share/ca-certificates/empathymachine.crt` | Trusted root CA | Linux |
| `/Library/Keychains/System.keychain` (entry) | Trusted root CA | macOS |
| Firefox profile NSS DB (`cert9.db`) | Firefox-trusted root CA | both, via `certutil` |

To wipe completely: `bash scripts/install_systemd.sh --uninstall` (or
`install_launchd.sh --uninstall`), `bash scripts/install_tray.sh --uninstall`,
`./empathymachine uninstall-cert`, then `rm -rf ~/.empathymachine`.

## Roadmap Ideas

- HTTP/2 and HTTP/3 interception support
- Richer blocklist syntax (Adblock filters)
- JSON-response rewriter (text substitutions on JS-shell sites like CNN)
- SIGHUP / file-watcher hot reload (eliminate the ~1s restart on blocklist/bypass edits)
- Admin API write endpoints (let MCP/tray talk to a long-running service instead of editing files + restarting)
- Container images for NAS / home-lab deployment

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## Disclaimer

EmpathyMachine is provided "as is" without warranties or guarantees. You are responsible for deploying it in accordance with local laws, network policies, and acceptable-use requirements.

## Why 'EmpathyMachine'?

<img src="https://upload.wikimedia.org/wikipedia/commons/e/ee/DoAndroidsDream.png" alt="Do Androids Dream of Electric Sheep? cover" width="160" align="right" />

The 'Empathy Machine' is a fixture in Phillip K. Dick's 'Do Androids Dream of Electric Sheep?' - a device that allows users of the dystopian world to “fuse” with others through shared experience. The participant grips two handles and is instantly connected to a collective hallucination where the user is made to feel empathy collectively. The empathy box serves as both a moral barometer and a coping mechanism in a world where real life (and authentic emotion) is scarce.
