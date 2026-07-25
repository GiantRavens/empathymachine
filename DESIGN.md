# EmpathyMachine — Design

> A reasoning engine for personal network policy, with a teed-up evolution
> into AI-mediated information environment shaping. This document is the
> orienting north-star for the project. Code ships against this vision.
> Read this before `CLAUDE.md`, `README.md`, or `PLAN.md` if you're new.

## 1. The problem we're solving

Personal device privacy today is **a graveyard of static configurations**.
You install Little Snitch, build up a few hundred per-app rules over a
year, forget why most of them exist, can't easily move them to another
device, and have no idea whether they're still appropriate. You install
Pi-hole on a Raspberry Pi, subscribe to a blocklist, and never look at
it again. You set browser settings, then forget the settings exist when
something breaks. **None of these tools talk to each other. None of them
carry the *reasoning* for a decision forward in time. None of them
*learn*.**

The result: most people have either no privacy posture or an
accreted-over-years black box of decisions nobody (including the user)
can audit.

## 2. The core thesis

EmpathyMachine is **the reasoning brain** for personal network policy.
Other tools (Little Snitch, Pi-hole, router firewalls, iOS profiles,
browser extensions) are **enforcement substrates**. The captain has
conversations with an LLM about what they want; those conversations
become **policy entries with traceable reasoning**; EM then propagates
those decisions to every substrate that can enforce them.

```
┌────────────────────────────────────────────────────────────┐
│                  Captain ↔ LLM (Claude)                    │
│   "Should I block QUIC?" → discussion → decision           │
└─────────────────┬──────────────────────────────────────────┘
                  ↓ writes
            ┌──────────────┐
            │  policy.yaml │  ← single source of truth
            │  + reasoning │     git-tracked, audit-able
            └──────┬───────┘
                   ↓ generates
   ┌───────────────┼────────────────┬─────────────────┐
   ↓               ↓                ↓                 ↓
EM rewriter   /api/lsrules    /api/hosts      /api/mobileconfig
(strip        (LS subscribes  (Pi DNS         (iOS subscribes
Alt-Svc)      via URL)        consumes)       to profile)
```

Every decision in policy.yaml carries `note:` (why), `decided_at:` (when),
`decided_by:` (captain/LLM), `review_by:` (revisit date). The git history
of policy.yaml is your privacy posture's evolution, fully replay-able.

## 3. The substrate ecosystem

EM doesn't replace any of these tools — it coordinates them.

| Substrate | What it enforces | What it observes (feeds back) |
|---|---|---|
| **EM proxy + rewriter** | Blocklist, bypass, HTML rewrites, header strips (Alt-Svc) | Request log, /api/metrics |
| **EM DNS sinkhole** | Blocklist at DNS layer | Query log |
| **Little Snitch** | Per-process firewall, kernel layer | JSON rule export, alert log |
| **Pi-hole / EM-on-Pi** | LAN-wide DNS sinkhole | Query log |
| **Router firewall** | LAN-wide L3/L4 rules | NetFlow, hit logs |
| **Tailscale** | VPN ACL | ACL hits, peer connections |
| **iOS / iPadOS .mobileconfig** | System-level DNS + proxy + content filter | (limited) |
| **Browser extensions** | Page-level filter | Block events |
| **OS-level (dtrace/eBPF)** | Observation only | Per-process connection trace |

Today: EM proxy + DNS, Little Snitch are wired. Pi/router/iOS/etc. are
future consumers of the same `policy.yaml` output.

## 3.5 Intelligence sources (read-only feeds into the policy brain)

Substrates *enforce* policy. **Intelligence sources** *inform* it. The
policy brain reasons better when it can draw on multiple knowledge
streams to classify what it's seeing.

| Source | What it knows | Status |
|---|---|---|
| **DuckDuckGo Tracker Radar** | ~1k classified trackers + ~5.5k domain→owner mappings | ✓ shipped (`mm explain <host>`) |
| **LLM general knowledge** | Long-tail hostnames DDG doesn't cover; reasoning about novel patterns | ✓ shipped (`mm explain` fallback via Anthropic / Ollama) |
| **research-forge** (sibling project at `notebook/forge/research-forge/`) | Deep evidence-first OSINT on people + entities — corporate structure, funding, employment history, privacy track record, recent news | ⊙ intersection designed, not wired |
| **Threat intel feeds** (MISP, AbuseIPDB, URLhaus) | Recent malicious-host indicators, phishing campaigns, C2 servers | ⊙ future |
| **EM's own history** | "Have I seen this host before? In what context? Allowed or blocked? Captain ever overrode?" | partial — `jobs.jsonl`-style log exists, no structured query yet |
| **Captain's own preferences** | "I prefer 'use' over 'utilize'", "I don't want celebrity news" — written into policy.yaml directly | ✓ shipped (config.yaml rewrites today; will graduate to policy.yaml entries) |

### Intersection with research-forge specifically

RF gives the policy brain **entity-depth** that DDG/LLM can't match. The
intersection has two natural directions:

**EM → RF**: when EM observes a new unclassified host repeatedly, the
policy brain can trigger a small RF mini-profile of the entity behind it.
The result lands in policy.yaml as `note:` context attached to whatever
decision the captain eventually makes.

**RF → EM**: during an active RF investigation, the target's known
domains (LinkedIn profile URL, Equilar pages, news sources cited)
should auto-route through EM with bypass enabled (full connectivity for
the duration of the run, no MITM friction, clean teardown after).
RF's `run_summary` lists the domains it touched; EM can ingest that
list.

**Both → LLM**: the richest pattern. Captain asks Claude "should I
allow X?". Claude calls `explain_host` (DDG + EM's general LLM) +
RF entity profile (if applicable) + EM history → synthesizes a
recommendation with provenance from all three. The captain's decision
inherits all three sources of reasoning.

Build order for the intersection: defer until the core EM → LS policy
loop (sections 4-6) is solid. Then the natural first wire-up is
`research_entity(domain)` as a new MCP tool that takes a hostname,
extracts the entity, and dispatches to RF — output feeds back into
`mm explain <host>` as the third tier (DDG → LLM → RF for entity depth).

## 4. The conversation pattern (motivating example)

How a real policy decision unfolds in this architecture:

> **Captain (talking to Claude via MCP):**
> "What's QUIC? Should I let it through?"
>
> **Claude (via `explain_host` + general knowledge):**
> "QUIC is HTTP/3 over UDP/443. Faster handshake, multiplexed,
> encrypted from byte 0. The catch: EM is HTTP-over-TCP — zero
> visibility into UDP/443. Every browser that negotiates QUIC silently
> exits your MITM tunnel. Given your stated priority of full
> inspection, blocking QUIC forces TCP fallback within ~1s, costs you
> ~50ms latency on first load. Trade looks good for you."
>
> **Captain:**
> "Block it."
>
> **Claude (via `policy_set`):**
> Updates `policy.yaml`:
> ```yaml
> network_policy:
>   block_quic:
>     value: true
>     decided_at: 2026-05-24T14:30:00Z
>     decided_by: captain (via Claude conversation)
>     note: "QUIC bypasses EM HTTP-over-TCP inspection. Blocking forces
>            TCP fallback so EM sees everything. Captain prioritizes
>            inspection over the ~50ms first-load latency."
>     review_by: 2026-11-24
> ```
> Regenerates `/api/lsrules` (LS pulls on next refresh; force with
> `mm ls-rule-refresh`). Strips Alt-Svc headers in EM rewriter on
> restart. Both substrates now enforce. Captain has a single auditable
> record of *why*.

This is the unit of work. Everything else is plumbing.

## 5. Cognitive Honing applied to network policy

(per the captain's standing doctrine in `~/.claude/CLAUDE.md`)

1. **Push logic down, keep orchestration up** — `policy.yaml` + LLM
   conversation are orchestration. Tools are dumb consumers. Adding a
   new substrate is "implement consumer of `policy.yaml`", not "port
   policy logic."
2. **Observe before you act (manifest)** — every request gets cheap
   classification (known tracker? known service? new host?) before
   expensive action (LLM lookup, content rewrite). The Manifest pattern
   keeps the hot path fast.
3. **Emit telemetry, not just results** — every decision carries *why*.
   `Blocked 4200 requests` is Level 0. `Blocked 4200: 1200 ad-network
   (DDG), 800 telemetry (MS/Adobe/Apple), 600 fingerprinting (DDG), 100
   LLM-classified, 0 unclassified-new` is Level 2.
4. **Detect the shift-left moment** — if 15+/week blocks come from the
   same unclassified host, promote it from runtime-LLM-classification to
   baked-into-blocklist. The system learns its own gaps.
5. **Design to be deleted** — `mm policy ...` today is CLI. Tomorrow
   it's a tray menu. Eventually it's an LLM-issued action with no
   captain in the loop for routine decisions.
6. **Recursive self-improvement** — weekly reflection: which decisions
   got reversed, which new patterns emerged, what should the policy
   adjust to. Captain reviews and approves; LLM proposes deltas.

## 6. The OODA loop, concretely

| Phase | Today (static) | This vision |
|---|---|---|
| **Observe** | Block-list match / pass | Full per-connection telemetry: app, host, owner, category, prevalence, response size, timing |
| **Orient** | Domain match | Pattern detection: "third new Adobe domain in 24h", "this app burst-talking after months silent" |
| **Decide** | Hardcoded yes/no | Policy + LLM reasoning: "given baseline, this is anomalous; given Adobe is known-quantity, allow with logging" |
| **Act** | Block or pass | Multi-substrate: update policy.yaml + push to LS via LSRules + log decision with reasoning |
| **Reflect** | (none — no memory) | Weekly review: what changed, what got reversed, what drifted, what new patterns emerged |

## 7. Reflection and learning loops

- **Daily**: one-line POTD entry — "EM blocked X, allowed Y, saw Z new
  hosts (top 3: ...)"
- **Weekly**: structured reflect — patterns, drift, captain-overrides
  analysis, suggested policy adjustments
- **Monthly**: deep reflect — "your inspection-coverage trended down
  4% — three apps moved more traffic to QUIC despite the strip rule;
  here's a proposal"
- **Bet tracking** — captain says "I bet allowing X won't break Y"
  → EM tracks Y's health over the bet period → review date arrives
  → "your bet was right/wrong, here's the data"

## 8. Adversarial dimension

Apps actively try to bypass network-layer inspection:

- DoH (DNS-over-HTTPS) to bypass DNS sinkhole
- Hardcoded IPs to bypass DNS entirely
- Certificate pinning to refuse MITM
- QUIC to bypass TCP-only inspection
- Direct WireGuard / VPN tunnels

EM's role: **detect bypass attempts and counter-recommend**. "Chrome
attempted DoH to 1.1.1.1, blocked. Consider also denying outbound :853
(DoT) to prevent the fallback." Policy.yaml gets a new entry with the
captain's decision; LSRules pushes the enforcement.

## 9. The presentation-shaping evolution (later direction)

Once the privacy-and-control layer is solid, the same substrate enables
**AI-mediated information environment shaping** — the captain's own AI
acting as editorial layer between the raw web and the captain's senses.

The captain is already doing simple versions of this via EM's existing
rewriter (text substitutions like "Trump" → "Orange Shitstain", "utilize"
→ "use"; modal removal; cookie-banner kill). The evolution:

**Removal** (today): take stuff away — trackers, modals, ads, banners.
Hygiene layer.

**Substitution** (today): replace language site-wide. Vocabulary
normalization.

**Annotation** (next): add context without modifying — "owned by Adobe",
"low-trust source", "this claim contradicted at [link]". The page is
unchanged but your AI is whispering context.

**Reframing**: instead of CNN's chosen headline, show your AI's summary
of the story from N sources. The page is rewritten to be useful-to-you
rather than optimized-for-engagement.

**Curation**: hide content categories. Captain-facing examples:

- "No coverage of so-called influencers anywhere."
- "No celebrity gossip."
- "No political horse-race / poll-of-the-day coverage."
- "No outrage-bait headlines."
- "No tech-CEO worship pieces."

Each compiles to: extract article text → LLM classifier ("is this about
X?") → hide or annotate the rendered element. **This is a content
operation, not a network operation** — best implemented as a browser
extension OR a reader-mode-style intermediate (e.g., a EM-served reader
mode that consumes news sites and re-presents them filtered) rather
than via the existing HTML element-remove rewriter, which operates on
markup without understanding subject.

Cost: ~1 LLM classification call per article. Mitigations: aggressive
per-URL caching (`~/.empathymachine/article-classification.sqlite`),
async post-render hiding so first paint isn't blocked, batched
multi-article prompts when many headlines on one page.

**Time-shifting**: "Never show me breaking news; only what's still
relevant after 24h." Slow-news mode by policy.

**Per-site editorial overlay**: invasive transformation of content from
specific sources. Captain-facing examples:

- "Rewrite stories on site X to remove framing bias."
- "Flag every unsourced claim in articles I read on site Y."
- "Insert links to primary sources where this site is paraphrasing them."
- "Rewrite headlines to be neutral statements rather than engagement bait."

This is the most powerful AND most dangerous shaping mode — it changes
words rather than hiding them. Per Section 10 dignity safeguards, this
must NEVER ship without: per-site opt-in, hover-to-see-original always
available, "raw mode" toggle, periodic exposure reporting, and a clear
visual indicator that text has been editorially transformed. Defer
until the simpler subtractive modes are operationally mature and the
dignity-safeguard tooling is built.

**Anti-manipulation overlay**: detect dark patterns (artificial scarcity,
fake countdowns, hidden unsubscribe links) and annotate or remove them.

**Cross-source synthesis**: don't show one site's coverage; synthesize
across your trusted sources.

**Factuality layer**: every factual claim flagged with confidence +
source check. Op-eds flagged as opinion. AI-generated content flagged.
Sponsored content flagged regardless of site disclosure.

### Why this is a category change

Current "personalization" optimizes *for the platform's metric* using
their model of you. This evolution optimizes *for your stated goals*
using your AI's model of you. **Same machinery, opposite orientation.**

## 10. Dignity safeguards (load-bearing — don't ship presentation
shaping without these)

The same architecture that gives you editorial control could become
silent reality-warping if we're not careful. These are non-negotiable
when we get to section 9 features:

1. **Audit-able** — every modification leaves a trace in policy.yaml.
   `mm explain-modification "Orange Shitstain"` returns "you set this
   substitution on 2026-03-14 with the note 'preferred vocabulary'."
2. **Reversible** — hover-to-see-original on substituted text. "Show
   me what this page looked like raw" should always be one keystroke
   away.
3. **Boundary-aware** — substitutions never apply to text copied to
   clipboard headed outside the device, nor to text typed into reply
   fields. The filter is for *consumption*, not for *production*.
4. **Periodic exposure** — opt-in "raw mode" days/hours where filters
   are off. Prevents skill atrophy and echo-chamber drift.
5. **Diff reporting** — weekly summary: "here's what was filtered last
   week, sample of 20." Prevents silent over-filtering.
6. **Contextual profiles** — filter off when working with others, on
   during personal browsing. Reality-shifting profiles are explicit and
   labeled in the UI.
7. **Anti-deception** — substitutions are never applied to quoted
   primary sources (court documents, scientific papers, archival news)
   where word-level accuracy matters.

The goal: editorial agency without epistemic isolation.

## 11. Anti-features (we won't ship without explicit reconsideration)

- **Engagement metrics** — don't optimize EM's own usage. Don't measure
  "time spent reading filtered content." This is a tool for cognitive
  sovereignty, not for capturing the attention it frees up.
- **Cloud sync of policy by default** — policy.yaml is private. If we
  ever support sync, opt-in, captain-owned (Syncthing-style, not
  cloud-service).
- **Automatic policy adoption from community** — a captain could opt-in
  to "import these decisions from a trusted source", but never silently.
  Avoids social manipulation by trusted-source compromise.
- **Aggregated telemetry sent off-device** — every byte of EM's
  telemetry stays local. If we ever expose metrics for a captain to
  share, opt-in, structured.
- **Dark-pattern UI for changing privacy posture** — the system is hard
  to set up but should never be hard to LOOSEN. Tightening can have
  friction (so it's deliberate); loosening must be a single command.

## 12. Glossary

- **Policy** — the captain's stated intentions in policy.yaml. Source
  of truth.
- **Substrate** — a tool that enforces policy. EM proxy, LS, Pi-hole,
  router, etc.
- **Decision** — one entry in policy.yaml with reasoning, decided_at,
  review_by.
- **Manifest** — cheap pre-classification of a request before expensive
  action.
- **Posture metric** — % of outbound traffic that is observed and
  policy-governed.
- **Reflection** — periodic review of what happened vs what was
  intended, feeding back into policy revisions.
- **Reasoning trace** — the captured conversation that produced a
  decision. Lives in `logs/policy-decisions/<timestamp>.md`.
- **Substrate-agnostic policy** — a policy entry that compiles to rules
  for multiple substrates (e.g., block_quic produces an EM Alt-Svc
  strip + an LS deny rule + a future router rule).

## 13. Status & roadmap

See [`PLAN.md`](PLAN.md) for current shipped/deferred/won't-ship
inventory. Ship order against this design doc:

1. ✓ EM proxy + DNS sinkhole + cert install + tray + bypass + system-proxy toggle
2. ✓ Little Snitch deny-rule importer (LS → EM, one-way)
3. ✓ Host explainer (DDG + LLM fallback)
4. ✓ **Alt-Svc strip** (EM rewriter, replaces with `Alt-Svc: clear` per RFC 7838 §4) — Section 4 motivating example shipped 2026-05-24
5. ✓ **policy.yaml schema + `mm policy` CLI** + first real reasoning-trace entry (`block_quic`) — Section 2 thesis shipped 2026-05-24
6. ✓ **`/api/lsrules` publisher** (closes EM → LS loop) — shipped 2026-05-24; LS subscribes once, every `mm policy` decision propagates
7. ✓ **MCP `policy_*` tools** (closes LLM → policy loop) — shipped 2026-05-24
7b. ✓ **`presentation_policy` section + compile to fenced regions** in config.yaml + managed `blocklists/policy_imports.txt` — shipped 2026-05-24. First entry: `block_anti_adblock_walls` (Hollywood Reporter / PMC siblings). `mm policy compile` is idempotent via fenced markers; re-running it cleanly updates managed regions without disturbing captain's hand-written entries.
8. ⊙ Reflection: daily POTD entry + weekly summary
9. ⊙ Posture metric in dashboard
10. ⊙ `/api/hosts` for future Pi-as-DNS deployment
11. ⊙ Research-forge intersection (`research_entity(domain)` MCP tool;
    explain-tier 3) — per Section 3.5
12. ⊙ Annotation overlay (first presentation-shaping move per Section 9)
13. ⊙ Dignity safeguards (per Section 10) — must precede aggressive shaping

⊙ = designed-but-not-shipped.

## 14. When in doubt

Re-read sections 2, 5, and 10. Architecture (2) tells you *how*.
Cognitive Honing (5) tells you *why we build the way we build*. Dignity
safeguards (10) tell you *what we won't do even if we technically could*.

Every PR should make at least one of those clearer or harder to violate.
