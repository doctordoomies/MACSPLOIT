# Changelog

All notable changes to MACSPLOIT are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) (pre-1.0: minor versions
may include breaking changes).

## [Unreleased]

- **OSINT foundation + Username/Email OSINT via user-scanner (M6 / #58, #22):** typed
  `USERNAME_OSINT` / `EMAIL_OSINT` capabilities and `username_osint` / `email_osint`
  chains with explicit, compatibility-checked provider selection; a shared `osint`
  core module (strict subject validation, provider-neutral positive/negative/blocked/
  error/unknown checks, bounded untrusted fields, graph mapping) for future providers;
  `Username`, `EmailAddress`, and `Account` assets with `has_account` / `profile_url`
  relationships and per-run observation metadata (migration 004); a dedicated SwiftUI
  OSINT section (subject/provider selection, explicit Run, Cancel, run state including
  `PARTIAL`, summary counts, reported accounts with `REPORTED` confidence, evidence and
  asset links, history after restart). The `user_scanner` provider supports
  user-scanner 1.5.x: `--username=`/`--email=` argv only, NSFW excluded, lowered
  concurrency, 10 s request timeout, 15-minute run limit, private per-run config that
  disables upstream's PyPI update prompt, and never `--cross-scan`, `--hudson`,
  proxies, or `--allow-loud`. The JSON report is stored byte-for-byte as its own
  hashed evidence before parsing; evidence is kept on cancel, timeout, tool failure,
  and malformed output. Identifier subjects are authorized by the explicit target and
  Run action, never by host scope, and only passive/low-impact OSINT providers may run.
  Discovery checks `MACSPLOIT_USER_SCANNER`, `PATH`, and pipx's `~/.local/bin`; install
  guidance is copy-only. Offline tests use `fixtures/fake-user-scanner.sh`.
- **Process supervisor:** output past the stdout/stderr cap is now drained and discarded
  instead of left in the pipe, so a chatty tool can no longer stall until its timeout.
- **DNS Recon for IP and URL targets (M1.4 follow-up):** DNS Recon now accepts Domain,
  Hostname, IP, and HTTP(S) URL targets. Domains/hostnames (and URL hostnames) resolve
  forward (A/AAAA); an IP target, or a URL whose host is an IP literal, does a reverse
  (PTR) lookup — PTR names become `Hostname` assets linked from the IP by a new
  `ptr_record` relationship (a PTR observation only, not forward-confirmed). URL hosts are
  extracted with structured parsing in the core; scope stays authoritative (the owner case
  `http://127.0.0.1/` runs once the IP is in scope). Native resolver gains bounded reverse
  lookup (migration 003).
- **Recon results in the live console (M1.4 follow-up):** a durable, bounded, sanitized
  `ProviderResults` event (count, by-type counts, and a capped preview of
  source→value/relationship) now drives concise result lines in the live console, with a
  "+N more — View Assets" hint and a completion summary. URL values are query-redacted;
  raw output stays only in evidence. Assets/Evidence/Activity remain authoritative.
- **Provider installation (M1.4 follow-up):** Provider Center can now actually install an
  external provider on explicit user action, with no shell and nothing silent. Installs are
  typed (provider id + method, never an arbitrary command); only the reviewed set
  (subfinder, httpx, katana, ffuf, nmap) is installable, and they run asynchronously with
  live status/cancellation.
  - **Install with Homebrew:** a shell-free `brew install <reviewed-formula>`
    (executable + argv, no `sudo`, never installs Homebrew itself).
  - **Install without Homebrew (managed direct download):** now implemented for
    subfinder/httpx/katana/ffuf as a native Rust pipeline. The exact artifact for the host
    architecture (arm64/x86_64) is chosen from a hardcoded, pinned manifest
    (version + HTTPS URL + SHA-256 + archive format + member); the download is HTTPS-only to
    reviewed GitHub release-asset hosts with capped host-checked redirects and a streamed
    size bound; the SHA-256 is verified before extraction; only the single reviewed
    top-level executable member is extracted (traversal/symlink/hardlink/duplicate/zip-bomb/
    malformed archives fail closed); and it is installed by an atomic `rename` into
    `~/Library/Application Support/MACSPLOIT/Providers/`, leaving any previous good binary
    intact on failure. Nmap has no managed download (privileged `.dmg`) and routes to
    Homebrew/official. No `curl`/`unzip`/`tar`/`sh`, no `curl | sh`, no remote scripts, no
    background updates — a new version is a reviewed manifest change. The pipeline is driven
    through an injectable transport so it is fully tested offline.
- **First-run setup & onboarding (Milestone 1.4):** a guided, versioned first-run
  experience shown before the workbench on a fresh install (or after a setup-version
  bump) and re-runnable from Settings → Setup & Environment without touching workspaces,
  evidence, SQLite, or installing anything. Steps: Welcome; a **required** authorization
  acknowledgement (Continue disabled until accepted; stored locally, explicitly not legal
  proof — scope and Authorize & Run remain separate, and the Rust core still enforces
  scope); Environment check (core/macOS/arch/providers/Homebrew — local facts only, no
  connectivity detection); Provider setup (reuses Provider Center data; Homebrew optional;
  never installs); Homebrew (optional, links to official instructions, no remote scripts);
  Appearance (System/Light/Dark, applied app-wide — replaces the forced dark mode);
  Interface detail (Standard/Advanced — presentation only, wired to the Recon live
  console default); Dashboard preset (Minimal/Operator/Research over the modular
  dashboard, Research = reserved non-fabricated area); an optional offline tutorial
  (Synthetic Recon, no network); and a Ready summary from real state. Setup state is a
  versioned app-preferences layer (UserDefaults) — not workspace SQLite — so progress
  resumes after a quit and completion survives restart. Existing users see onboarding once
  after upgrading with their data intact. The app root now owns a single core boot
  lifecycle so Setup → Workbench never spawns duplicate observers.
- **UX stabilization (Milestone 1.3):** a responsive workbench pass with a core-backed
  authorization flow. Recon replaces the cramped segmented picker with adaptive workflow
  cards and a single execution panel (target, authorization state, provider readiness,
  options, Run/Cancel, a persistent "only scan what you are authorized to assess"
  reminder) plus a collapsible, read-only **live console** built from durable events and
  provider runs — including a display-only sanitized command (`$ nmap -sT …`, executable
  basename + argv, with HTTP(S) URL query values redacted to `?<redacted>`; never a shell
  string, never executed, no environment or secrets — the exact argv stays only in the
  hashed evidence envelope). Out-of-scope targets
  get an explicit **Authorize & Run** confirmation that adds only the narrowest exact
  scope entry (never a wildcard, CIDR, sibling host, or resolved IP), persists it, and
  re-checks core authorization before launching — via two additive, read-reuse protocol
  commands (`target_scope_status`, `authorize_target`) so Swift never reimplements scope
  matching. The Rust core remains the authorization boundary. The dashboard is rebuilt as
  calm modular cards from real workspace state, the sidebar no longer overlays content,
  and the Tool Manager becomes **Provider Center** with Homebrew presented as an optional
  recommended install method rather than a requirement. No new network behavior; offline
  tests cover scope status, authorization, and the console model.
- **Direct IP Recon (Milestone 1.2):** a new `IP Recon` chain (`ip_recon`) that runs
  Nmap → HTTPX directly from one explicitly selected, in-scope IPv4 or IPv6 address —
  no domain, no DNS, and no Subfinder step. It reuses the existing Nmap and HTTPX
  providers, asset graph, evidence, scope enforcement, cancellation, and provider-status
  UI unchanged; the conservative Nmap profile is not altered. Scope stays authoritative
  (exact IP or a containing CIDR authorizes; a CIDR is never expanded into a sweep and
  only the selected IP is scanned — unrelated workspace IPs are not). Includes a narrow
  HTTPX fix so IPv6 probe URLs are correctly bracketed (`http://[2001:db8::10]:443`) and
  IPv6 Websites link back to their host IP. Adds an `IP Recon` UI mode with the Nmap/HTTPX
  provider panel and an IPAddress-target compatibility hint. Offline fake-tool coverage.
- **Local & private web targets (Milestone 1.1):** `localhost`, loopback
  (`127.0.0.0/8`, `::1`), explicitly scoped private IPs/CIDRs, `.localhost`, and
  `/etc/hosts` dev names are now first-class for the web workflows — Web Analysis, Web
  Recon, and Content Discovery run directly against a locally running app with custom
  ports and IPv6 URL syntax, with no public DNS and no Domain target required. Local or
  private status never implies authorization: the target host must be in explicit
  workspace scope, which the Rust core enforces. Cross-host redirects and crawl/ffuf
  discoveries remain fail-closed (distinct `localhost` / `127.0.0.1` / `::1` identities;
  no automatic scope widening; cloud-metadata hosts are never auto-probed). Adds a
  non-authoritative "LOCAL TARGET" UI indicator, local scope quick-fill and guidance,
  and offline tests across classification, scope, and all three web providers.
- **Content Discovery (Phase 2C):** an external `ffuf` provider (ACTIVE) and a
  `Content Discovery` chain for bounded path discovery over an explicitly selected
  in-scope HTTP(S) URL with a user-chosen wordlist. The wordlist is validated in the
  core (≤ 500 entries, ≤ 1 MiB, ≤ 512-byte lines; `#` comments/blanks ignored) and
  passed as a typed `start_chain` option; ffuf runs a fixed, bounded profile (top
  status codes, 10 threads, 10 req/s, 5 s timeout, no redirects, no recursion).
  Accepted results become same-host `URL` assets with `has_endpoint` links; 404s
  create no asset; raw output is hashed evidence and the persisted command redacts the
  local wordlist path to its file name. Never runs as part of another chain. Offline
  fake-tool coverage.
- **Tool Manager / Provider Center:** global native provider inventory with filters,
  version/path diagnostics, explicit installation states, and static copy-only setup
  help. Refresh retains prior results on failure and prevents duplicate requests.
  Protocol v1 adds optional executable paths and provider-owned setup metadata.
  Synthetic now correctly reports Built In; failed version probes report Error.
  No provider installation, updates, or scans are triggered by this interface.

- **Recon usability:** added editable workspace scope, a built-in `DNS Recon`
  workflow for in-scope Domain/Hostname targets, provider refresh/install guidance,
  URL-target assistance for web workflows, and live-capable UI/core messaging. Missing
  external providers are now explained instead of making the Run control appear
  mysteriously unavailable. Scope enforcement remains authoritative in the Rust core.
- **Native HTTP Analysis (Phase 2B):** a built-in `native_http` provider (no external
  tool) and a `Web Analysis` chain that analyze an explicitly selected in-scope
  HTTP(S) URL — response + security headers, cookie security flags (never values),
  CORS headers, a scope-checked redirect chain, and conservative robots.txt parsing —
  behind an injectable, offline-testable `WebTransport`. ACTIVE_LOW_IMPACT; bounded
  redirects/body/time; TLS validation left on; results enrich the `Website` asset with
  durable evidence. Independent of Katana.
- **Katana Web Recon (Phase 2A):** bounded same-host crawling from an explicitly
  selected in-scope HTTP(S) URL into URL assets, with evidence, provenance,
  cancellation, depth/time/output limits, and offline fake-tool coverage.

Preparing the first public beta: Apache-2.0 license, community-health files,
contributor and threat-model documentation, CI, and a security review. No public
release has been made yet.

## [0.1.0] - Unreleased (public beta candidate)

The first credible public beta: a native macOS reconnaissance workbench with a
modular provider pipeline, scope enforcement, evidence, and asset correlation.

### Added

- **Foundation (Phase 0):** SwiftUI app ↔ Rust core (`macsploit-core`) over a
  line-delimited JSON pipe; per-workspace SQLite with migrations; target
  classification; asset graph (assets, relationships, observations); scope engine;
  task/chain state machine; hash-verified evidence; durable events with replay;
  and a fully offline **Synthetic Recon** chain.
- **Subfinder provider (Phase 1A):** passive subdomain discovery via the external
  ProjectDiscovery `subfinder` tool, through a centralized shell-free process
  supervisor with executable discovery, version detection, JSONL parsing, evidence,
  and scope enforcement.
- **Native DNS provider (Phase 1B):** built-in A/AAAA resolution
  (`hickory-resolver`, system resolver config) turning subdomains into IP assets
  with `resolves_to` relationships; bounded timeout/concurrency, partial-success
  handling, and an injectable resolver for offline tests.
- **Nmap provider (Phase 1C):** conservative, unprivileged active port/service
  discovery (`-sT -sV --top-ports 100 -oX -`, no NSE, no root), XML parsed with
  `roxmltree` into Port/Service assets and `exposes`/`serves` relationships, with a
  per-provider timeout and a per-IP scope recheck.
- **HTTPX provider (Phase 1D):** low-impact HTTP/HTTPS probing of discovered web
  services into Website/Technology assets with `has_endpoint`/`uses_technology`
  relationships.
- **Domain Recon chain:** Subfinder → DNS → Nmap → HTTPX, with provider status
  (installed/missing/built-in) and risk labels surfaced in the UI.

### Security

- Shell-free process supervision with argument arrays, bounded stdout/stderr,
  per-provider timeouts, and process-group cancellation (no orphaned scans).
- Scope enforcement across families/CIDR/wildcards and per-asset for active
  providers; out-of-scope resolved IPs are never actively scanned.
- Evidence-first: raw provider output preserved and SHA-256 verified before parsing.
- No telemetry.

[Unreleased]: https://github.com/doctordoomies/MACSPLOIT/commits/main
