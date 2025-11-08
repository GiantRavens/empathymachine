# EmpathyMachine Planning Document

## Vision

Deliver a robust, high-performance man-in-the-middle HTTP(S) proxy that filters biased or malicious content, rewrites HTML/CSS streams, and provides actionable reporting comparable to or better than Pi-hole. The system should be LAN-friendly, easy to update, and extensible for future policy modules or UI enhancements.

## Success Criteria

- Transparent reverse proxy for HTTP/HTTPS with on-the-fly TLS interception.
- Configurable blocking of ad/tracker sources, sensitive content, and suspicious requests.
- Streaming HTML/CSS rewriting (phrase substitutions, iframe stripping, cosmetic adjustments).
- Compatibility with common blocklist formats (hosts-style lists, Adblock Plus syntax such as EasyList/EasyPrivacy, AdGuard).
- Operational visibility (dashboards, per-rule hit counts, latency metrics) on par with or exceeding Pi-hole.
- Portable binaries for Linux/macOS, plus container images for NAS/home-lab deployment.

## Target Deployment & Packaging

1. **Standalone binary** compiled via Cargo (musl static builds for Linux, native for macOS).
2. **Container image** based on Debian slim with health checks and `docker-compose` sample.
3. **Optional appliance VM** (cloud-init ready) for turnkey setups; lower priority but supported by the same binaries.

## High-Level Architecture

| Layer | Responsibility | Key Technologies |
| --- | --- | --- |
| Edge Listener | Accept inbound proxy connections (HTTP CONNECT, HTTP/2) | `tokio`, `hyper`, `tower` |
| TLS Authority | Issue on-the-fly leaf certificates signed by local CA | `rustls`, `rcgen`, persistent CA key store |
| Rule Engine | Compile and evaluate domain/path/element rules | `serde_yaml` configs, hosts parser, ABP rule parser, `aho-corasick`/regex |
| Content Rewriter | Apply streaming HTML/CSS transformations | `lol_html`, custom CSS injectors |
| Policy Runtime | Pluggable filters (blocking, tagging, logging) | `tower` layers, WASM/Lua extension option (future) |
| Admin API | CRUD for rules, certs, telemetry | `axum` (REST) + `serde_json`, `sqlx`/`sqlite` |
| UI Layer | Dashboard & rule editor | SPA (Svelte/React) served via admin API |
| Observability | Metrics, structured logs, tracing | `tracing`, `tracing-subscriber`, `prometheus` exporter |
| Persistence | Config snapshots, cert cache, telemetry rollups | `sqlite` (via `sqlx`) or `sled` |

## Core Components & Responsibilities

### Reverse Proxy Service

- Asynchronous pipeline with `hyper` server and `tower` middleware.
- CONNECT tunneling with selective inspection (certificate pinning bypass list).
- Request/response hooks that mimic current Python addon semantics.

### TLS Certificate Manager

- Generate local root CA if absent; store securely (file + optional passphrase).
- On-demand leaf certificate issuance via `rcgen`, cached by SNI.
- Provide CLI/admin endpoints to export root CA bundle for clients.

### Rule Engine

- Ingest hosts-format lists for domain/IP blocking (e.g., StevenBlack, Pi-hole gravity lists).
- Parse Adblock Plus syntax for URL and cosmetic filters (EasyList/EasyPrivacy, AdGuard).
- Refresh blocklists incrementally with ETag support and signature verification when available.
- Compile rules into efficient data structures (radix tree for domains, Aho–Corasick for path/selectors).

### HTML/CSS Rewriting

- Apply streaming `lol_html` transforms to avoid buffering entire responses.
- Maintain phrase rewrite tables with case-insensitive boundary matching (porting current behavior).
- Remove or hide iframes and ad containers; inject `.hidden` CSS when necessary.
- Optionally rewrite inline styles and linked stylesheets.

### Admin & Telemetry Subsystem

- Authenticated REST API exposing rule management, manual overrides, certificate status, and metrics.
- SPA dashboard supporting live search, rule testing, per-device analytics, and CA downloads.
- Prometheus/OpenMetrics exporter and structured logging via `tracing`.

### Persistence & Configuration

- Canonical configuration file (`config.yaml`) parsed with `serde`, layered with environment overrides.
- SQLite (via `sqlx`) for telemetry rollups, admin accounts, and certificate metadata.
- File-backed cache for downloaded blocklists with scheduled refresh jobs.

## Development Roadmap

1. **Phase 0 – Project Infrastructure**
   - Initialize Rust workspace, linting (`cargo fmt`, `clippy`), and CI pipeline.
   - Establish container build (Dockerfile + `cargo-chef`) and release automation.

2. **Phase 1 – Core Proxy Pass-Through**
   - Implement HTTP/HTTPS forwarding with CONNECT support.
   - Integrate `rustls` for TLS negotiation without rewriting.

3. **Phase 2 – Dynamic TLS Interception**
   - Add CA generation, leaf issuance, and certificate cache persistence.
   - Provide CLI to export/import the root certificate.

4. **Phase 3 – Rule Engine Foundations**
   - Enforce hosts-format blocklists at the request stage.
   - Emit structured block decision logs with `tracing`.

5. **Phase 4 – ABP Rule Support and Policy Plugins**
   - Parse EasyList/EasyPrivacy syntax for URL and cosmetic rules.
   - Implement modular `tower` layers and plan optional WASM/Lua extensions.

6. **Phase 5 – Streaming HTML/CSS Rewriting**
   - Integrate `lol_html` streaming transformations.
   - Port phrase rewrite logic, iframe blocking, and CSS injection.

7. **Phase 6 – Admin API & UI**
   - Build REST API with `axum` and secure with token/session auth.
   - Ship a minimal SPA dashboard for metrics, rule management, and cert download.
   - Persist configs and telemetry with SQLite.

8. **Phase 7 – Observability and Reporting**
   - Add Prometheus metrics exporter and per-rule counters.
   - Produce Pi-hole-style summaries (top domains, blocked requests, device breakdown).

9. **Phase 8 – Performance Hardening and Packaging**
   - Stress test (`criterion`, `wrk`, `vegeta`) and optimize hotspots.
   - Finalize binary distributions and Debian-based container image.
   - Document deployment and upgrade procedures.

10. **Phase 9 – Optional Appliance Image**
    - Build a Debian cloud/VM image with managed updates.

## Open Questions

- Preferred authentication model for the admin UI (local accounts vs. SSO/OAuth).
- Desired extension mechanism for user scripts (WASM, Lua, or declarative only).
- Required level of IPv6 support for LAN deployments.
- Whether to include DNS-level blocking (Pi-hole-style) or focus solely on HTTP proxying.
- Blocklist refresh cadence and need for differential updates.

## Next Steps

1. Confirm open-question decisions, especially admin auth and DNS scope.
2. Bootstrap the Rust workspace within `empathymachine/` and wire up CI/build tooling.
3. Begin Phase 1 development with minimal proxy pass-through and structured logging.
