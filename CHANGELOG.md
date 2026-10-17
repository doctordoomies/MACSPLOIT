# Changelog

All notable changes to MACSPLOIT are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) (pre-1.0: minor versions
may include breaking changes).

## [Unreleased]

- **Durable Findings and normalized result foundation (#76, parent #68) — owner
  acceptance pending:** a first-class, durable **Finding** entity (migration 008) — a
  reviewable analyst security conclusion that *references* durable records (affected
  canonical assets, multiple evidence, source provider/run) rather than copying provider
  stdout. Severity / confidence / lifecycle status are three independent typed dimensions;
  the lifecycle is a small core-validated state machine with append-only history; text and repeated
  fields are bounded and CVE/CWE identifiers are shape-validated; cross-workspace references are rejected.
  A shared typed **ResultProjection** read model derives normalized, provenance-carrying
  result items from the durable graph for a chain (never raw stdout or an opaque blob) —
  the internal results contract for Recon/OSINT/Findings/future reports/AI. New
  `WorkspaceView` **Findings** workbench (master/detail, New Finding, validated status
  changes with notes, evidence link/unlink, history) and a **Create Finding from a
  result** action on Recon/OSINT runs that prefills only factual references (asset,
  evidence, source) — the analyst writes the conclusion. No automated Finding creation
  yet (reviewed scanner-proposed Findings come later). Protocol (v1, additive):
  `create_finding`, `update_finding`, `set_finding_status`, `link_finding_evidence`,
  `unlink_finding_evidence`, `result_projection`; findings added to the snapshot. See
  [docs/findings.md](docs/findings.md).
- **M6 OSINT owner-acceptance fixes (#71, #72, #73 on #70) — owner acceptance pending:**
  - *Domain Authorize & Run (#71):* an out-of-scope Domain OSINT target now uses the same
    core-backed exact-entry **Authorize & Run** flow as Recon (via `target_scope_status`
    / `authorize_target`) instead of a generic out-of-scope error. The run starts only
    after the core adds and re-checks the one exact scope entry; Cancel or a failed
    authorization launches nothing; Username/Email/Phone identifier subjects never consult
    host scope.
  - *Typed results, not zero counters (#73):* OSINT results now dispatch on one durable
    typed workflow (parsed case-insensitively from `subject_kind`, which Domain now also
    emits as SCREAMING_SNAKE_CASE `DOMAIN`) instead of fragile lowercase string compares.
    A successful Phone run renders a **Phone intelligence** card (E.164 number plus the
    country, country code, carrier, number range, city, and formats actually reported,
    each with its source) rather than empty account tiles; Domain renders its passive
    records. Completion/partial/cancelled copy is workflow-aware ("The phone intelligence
    lookup completed.", etc.).
  - *Actionable installation + Install Console (#72):* missing reviewed providers now have
    an in-app **Install with MACSPLOIT** action (the core resolves a checksum-verified
    binary download or, for the Python providers, a pinned/verified `uv` runtime that
    installs the reviewed pinned package into an isolated environment — no system Python,
    pip, pipx, sudo, or system-directory writes). A read-only **Install Console** streams
    typed install events (stage, the reviewed executable + argv, bounded stdout/stderr,
    exit, cancellation) and the detected path/version; provider readiness refreshes
    automatically on completion. It is not a shell. Raw pip/pipx is demoted to a manual
    alternative. Homebrew remains optional.
- **M6 OSINT provider coverage and correlation (#58; #64, #65, #66, implementation
  portion of #67) — owner acceptance pending:**
  - *Email (#64):* socialscan now supports Email OSINT (registered / not registered /
    failed lookup kept distinct) and accepts upstream 2.x, including its
    `"True"`/`"False"` string booleans (previously every such record would have been
    an error and 2.x reported unsupported). Holehe reviewed and not integrated.
  - *Phone (#65):* `PhoneNumber` target/asset (strict E.164, `+` required, no country
    guessing) and a PhoneInfoga 2.x provider limited to the offline `local` and OVH
    public number-range scanners, parsed with a strict console grammar.
  - *Domain (#66):* `domain_osint` chain on in-scope domains with PASSIVE providers
    only: built-in certificate transparency (crt.sh) and RDAP (IANA bootstrap,
    allow-listed redirects, minimized registration facts) over a new bounded
    `fetch_bounded` transport, and theHarvester 4.10/4.11 with a fixed key-less
    passive source allow-list. Hosts share Subfinder's `Subdomain` type; new
    `has_email`, `has_nameserver`, and `observed_ip` relationships (migration 006).
    OWASP Amass reviewed and not integrated.
  - *Correlation (#67):* explicit, evidence-backed, reviewable correlations with an
    append-only review log (migration 007; `propose_correlation`,
    `review_correlation`, `snapshot.correlations`); never merges assets. SpiderFoot
    reviewed and not integrated. Four-workflow acceptance, restart, and
    failure-semantics tests.
  - OSINT view gains Phone and Domain workflows, domain observation provenance, and
    correlation review controls (functional changes only). All tests offline.

- **Username OSINT provider wave: Sherlock, Maigret, socialscan (M6 / #58):** three
  username-only OSINT providers on the existing typed contract, each an evidence-first,
  bounded, shell-free, cancellable run selectable per OSINT run alongside user-scanner.
  Sherlock parses its CSV (`exists == Claimed` → account), Maigret its `--json simple`
  report (claimed sites only), and socialscan its `--json` registration-availability
  records (taken+valid → account). A shared `providers::osint_cli` module adds the
  pip/pipx discovery, private contained run directory/`HOME`, symlink-safe ≤1 MiB report
  capture, and version classification; all three normalize through `osint::build_output`,
  so cross-provider discoveries of the same public profile deduplicate into one canonical
  `Account`/profile-`URL` asset while each provider keeps its own observation, evidence,
  and provenance (nothing silently merges identities). No logins, credential checks,
  breach data, recursion, proxies, or anti-blocking; not in the managed-download
  installer (copy-only `pipx`/`pip` setup guidance). Offline fixtures only
  (`fixtures/fake-{sherlock,maigret,socialscan}.sh`); the Provider Center and OSINT
  picker list them dynamically.
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
