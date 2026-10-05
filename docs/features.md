# MACSPLOIT feature status

This is the **authoritative** status matrix. It reflects what the code actually does
today, not aspirations. Statuses:

- **STABLE** — implemented, tested, and expected to remain compatible pre-1.0.
- **BETA** — implemented and tested, but may change before 1.0.
- **EXPERIMENTAL** — implemented but rough / narrow / subject to change.
- **PLANNED** — designed/intended, not yet implemented.
- **FUTURE** — deliberately out of scope for the near term.

## Foundation

| Capability | Status | Notes |
| --- | --- | --- |
| Workspaces | STABLE | Isolated per-workspace SQLite under Application Support |
| Workspace scope editing | BETA | Replace normalized domain/wildcard/IP/CIDR scope after creation; audited and persisted |
| Target classification | STABLE | Domain/URL/IP/CIDR/email/username/hostname, IDNA |
| Scope enforcement | STABLE | Exact/wildcard/CIDR, IPv4/IPv6, per-asset for active providers |
| Local & private web targets | BETA | `localhost`/loopback/`::1`/private IP/CIDR/`.localhost`/`/etc/hosts` names as first-class web targets with custom ports; no public DNS; scope still authoritative; `localhost`≠`127.0.0.1`≠`::1` |
| Direct IP Recon | BETA | Explicit in-scope IPv4/IPv6 → Nmap → HTTPX; no DNS prerequisite; one selected IP only (no CIDR expansion); IPv6 probe URLs bracketed |
| Recon authorization flow | BETA | Core-backed `target_scope_status`; "Authorize & Run" adds only the narrowest exact scope entry (no wildcard/CIDR widening), persists it, and re-checks core authorization before launch |
| Live execution console | BETA | Read-only, collapsible console from durable events/provider runs, incl. a display-only sanitized command (executable basename + argv; no shell, env, or secrets) |
| Provider setup (Homebrew optional) | BETA | Provider Center + Recon present Homebrew as an optional recommended install method; existing executables on PATH or an explicit override are first-class |
| First-run setup & onboarding | BETA | Versioned guided setup (welcome, required authorization acknowledgement, environment, providers, optional Homebrew, appearance, interface detail, dashboard preset, optional offline tutorial); resumable and re-runnable from Settings; never installs software or touches workspace data |
| Appearance preference | BETA | System / Light / Dark, persisted and applied app-wide |
| Interface detail (Standard/Advanced) | BETA | Presentation-only default; Advanced expands the Recon live console by default. Never changes security capability |
| Dashboard presets | BETA | Minimal / Operator / Research starting layouts over the modular dashboard (Research shows a reserved, non-fabricated area) |
| Asset graph / data model | STABLE | Assets, relationships, observations, provenance |
| Evidence | STABLE | Raw provider output preserved, SHA-256 verified |
| Activity / events | STABLE | Durable, replayable |
| Persistence | STABLE | Survives restart; migrations versioned |
| Synthetic Recon (offline demo) | STABLE | Full pipeline with invented data, no network |
| DNS Recon | BETA | Built-in forward (A/AAAA) for Domain/Hostname/URL-host and reverse (PTR) for IP/URL-IP targets; no external CLI |
| Provider installation | BETA | Explicit, shell-free install of the reviewed provider set (async, live status): Homebrew, or a verified app-managed direct download (pinned manifest, HTTPS-only, SHA-256, safe extraction, atomic install) for subfinder/httpx/katana/ffuf; Nmap is Homebrew/official only; existing-binary/PATH first-class; no silent installs, no background updates |
| Recon result summaries | BETA | Bounded, sanitized `ProviderResults` events render concise discoveries in the live console (Assets/Evidence remain authoritative) |

## Providers (recon pipeline)

| Capability | Status | Notes |
| --- | --- | --- |
| Subfinder (subdomains) | BETA | External tool; passive |
| Native DNS (A/AAAA) | BETA | Built-in; hickory-resolver; ACTIVE_LOW_IMPACT |
| Nmap (ports/services) | BETA | External; ACTIVE; `-sT -sV --top-ports 100`, no NSE, no root |
| HTTPX (HTTP probing) | BETA | External; ACTIVE_LOW_IMPACT; Website/Technology assets |

## Web reconnaissance (deeper)

| Capability | Status | Notes |
| --- | --- | --- |
| Web crawling (Katana) | BETA | Bounded same-host standard-mode crawl; depth 2; explicit URL target; evidence/provenance preserved |
| Content discovery (ffuf) | BETA | External `ffuf`; ACTIVE; own `Content Discovery` chain; explicit user-selected wordlist (≤500 entries); bounded; no recursion |
| Historical URL collection (gau/waybackurls) | PLANNED | |
| Technology detection | BETA | Basic, via HTTPX tech fingerprints |
| Native HTTP analyzers (headers/CSP/cookies/CORS/robots) | BETA | Built-in `native_http`; ACTIVE_LOW_IMPACT; `Web Analysis` chain; cookie flags only (no values) |
| JavaScript analysis | PLANNED | |
| API discovery (OpenAPI/Swagger/GraphQL) | PLANNED | |
| Screenshots | PLANNED | |

## Assessment

| Capability | Status | Notes |
| --- | --- | --- |
| TLS analysis | PLANNED | Native or provider-backed |
| Vulnerability assessment (Nuclei) | PLANNED | Detection-only, conservative defaults |
| SQL injection assessment (sqlmap) | FUTURE | Detection-only if added; deeper behavior gated behind authorized-validation |
| Findings engine | PLANNED | Severity/confidence separate; dedup/correlation |
| Reporting (JSON/Markdown/HTML) | PLANNED | PDF later |

## OSINT

| Capability | Status | Notes |
| --- | --- | --- |
| Username (Sherlock/Maigret) | PLANNED | |
| Email (Holehe/theHarvester) | PLANNED | |
| Phone (PhoneInfoga) | PLANNED | |
| Domain OSINT | PLANNED | |
| Source/secret analysis (Gitleaks/TruffleHog/Semgrep) | FUTURE | Only on explicitly selected repos/files |

## Platform & tooling

| Capability | Status | Notes |
| --- | --- | --- |
| Tool Manager (status/version/path/help) | BETA | Global Provider Center with status, version, executable path, filters, diagnostics, copy-only setup help, and explicit per-provider install (Homebrew, or verified managed download for subfinder/httpx/katana/ffuf) — see the Provider installation row |
| Provider/plugin SDK | EXPERIMENTAL | Internal trait documented; no stable public ABI pre-1.0 |
| Reporting exports | PLANNED | |
| Workspace delete/export | PLANNED | Data location documented today |

## Lab / hardware (future, deliberately separated)

| Capability | Status |
| --- | --- |
| Authorized Validation / lab mode | FUTURE |
| Wireless / Wi-Fi Pineapple / SDR / Bluetooth | FUTURE |
| USB HID lab tooling / Pico / Rubber-Ducky-class | FUTURE |
| Cloud / Containers / Kubernetes | FUTURE |
| Raspberry Pi agents | FUTURE |

These are **not** implemented and are intentionally kept out of the default path.
MACSPLOIT does not ship workflows centered on credential theft, persistence, covert
surveillance, uncontrolled HID payloads, or automatic exploitation.
