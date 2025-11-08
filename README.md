# EmpathyMachine

EmpathyMachine is a Rust-based HTTP/HTTPS proxy designed to block trackers and ads while letting you inspect or intercept TLS traffic when you trust the generated root certificate. It succeeds the earlier Python prototype called middleman and focuses on performance, modern TLS support, and flexible blocklist management.

Unlike DNS-only solutions such as Pi-hole or AdGuard Home, EmpathyMachine operates at the HTTP layer as well, allowing on-the-fly content rewrites, TLS interception for deeper inspection, and per-request decisions informed by both DNS and application data. It coexists with traditional network blockers like the excellent Little Snitch. 

Use it to streamline and quiet your personal web experience by removing or rewriting entire web page sections or common patterns on the fly, even replace mindless jargon like "utilize" with "use". 

## Responsible Use

Use **EmpathyMachine** to understand the scope and impact of aggressive ad and tracking tech as you browse, but "with great power comes great responsibility": only intercept traffic you own or have permission to inspect, and stay within local laws and site terms of service.

## Key Features

- **Hosts-format blocklists** – Load local files or fetch remote lists (Steven Black, OISD, etc.) to deny matching domains or URL path fragments.
- **HTTPS interception with rcgen 0.14 + rustls 0.21** – Generates and persists a self-signed CA, automatically issues leaf certificates per host, and performs MITM for inspection.
- **Configurable bypass allowlist** – Skip interception for pinned or unsupported services by listing exact domains or wildcard suffixes (for example, `gateway.icloud.com` or `*.microsoft.com`).
- **DNS sinkhole with trust-dns** – Runs a local resolver that answers blocked domains with `0.0.0.0`/`::` (or NXDOMAIN) and forwards everything else to secure upstreams (DoT/DoH/DNSSEC).
- **CLI utilities & wrapper** – The `./empathymachine` launcher wraps `cargo run` and exposes shortcuts like `start`, `dump-ca`, and `refresh-blocklists`. Under the hood the binary still accepts flags such as `--dump-ca` to print the root certificate PEM or `--refresh-blocklists` to fetch remote sources and exit.
- **Rich logging** – Uses `tracing` to show blocked requests, TLS interception outcomes, and blocklist refresh status.

## Requirements

- Rust toolchain (Rust 1.75+ recommended) and Cargo
- macOS/Linux environment (tested primarily on macOS)
- Network clients configured to use the proxy (`127.0.0.1:8080` by default)

## Getting Started

1. Clone the repository and enter the project directory:

    ```bash
    git clone https://github.com/GiantRavens/empathymachine.git
    cd empathymachine
    ```

2. (Optional) Copy the sample configuration and edit `config.yaml` as needed:

    ```bash
    cp config.sample.yaml config.yaml
    "${EDITOR:-nano}" config.yaml
    ```

3. Launch the proxy with the wrapper script (it creates CA material on first run):

    ```bash
    ./empathymachine start
    ```

    Add `--update-lists` to refresh remote blocklists before starting, or append `-- --args` to forward extra flags to the underlying `cargo run`.

4. Trust the generated CA so browsers accept intercepted certificates:

    ```bash
    ./empathymachine dump-ca > empathy-root.pem
    ```

    Import `empathy-root.pem` into your OS/browser trust store (on macOS use **Keychain Access → System → File → Import Items…**, then mark **Always Trust** under *Trust*).

5. Point your browser or tooling at the proxy address (`127.0.0.1:8080` unless overridden).

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

## Roadmap Ideas

- HTTP/2 and HTTP/3 interception support
- Richer blocklist syntax (Adblock filters)
- Analytics suite
- Web UI for interactive rule management or monitoring
- Container images and systemd integration

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## Disclaimer

EmpathyMachine is provided "as is" without warranties or guarantees. You are responsible for deploying it in accordance with local laws, network policies, and acceptable-use requirements.

## Why 'EmpathyMachine'?

<img src="https://upload.wikimedia.org/wikipedia/commons/e/ee/DoAndroidsDream.png" alt="Do Androids Dream of Electric Sheep? cover" width="160" align="right" />

The 'Empathy Machine' is a fixture in Phillip K. Dick's 'Do Androids Dream of Electric Sheep?' - a device that allows users of the dystopian world to “fuse” with others through shared experience. The participant grips two handles and is instantly connected to a collective hallucination where the user is made to feel empathy collectively. The empathy box serves as both a moral barometer and a coping mechanism in a world where real life (and authentic emotion) is scarce.
