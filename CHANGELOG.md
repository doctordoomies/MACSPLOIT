# Changelog

All notable changes to MACSPLOIT are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) (pre-1.0: minor versions
may include breaking changes).

## [Unreleased]

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
