# MACSPLOIT

**A native macOS modular security reconnaissance and assessment workbench for
authorized testing.**

MACSPLOIT models an engagement as a durable graph of **targets → assets →
relationships → evidence**, produced by modular **providers** (wrappers around
security tools, or native capabilities) and organized into **Recon Chains**.
Scope is a first-class safety boundary, every discovery keeps its provenance and
raw evidence, and the whole thing runs locally with no telemetry.

> **Status: v0.1 public beta (pre-1.0).** APIs, schemas, and the provider contract
> may change between pre-1.0 releases. See [feature status](docs/features.md).

---

## What it does today

```
Domain
  └─ Subdomain Discovery      (Subfinder)
       └─ DNS Resolution      (native, built-in)
            └─ IP Address
                 └─ Port + Service Discovery  (Nmap, conservative & unprivileged)
                      └─ HTTP Probing         (HTTPX)
                           └─ Website / Technology
```

Every stage is a provider selected by **capability**; results flow through
normalization → SQLite persistence → durable events → the SwiftUI app, with
per-asset **scope enforcement**, **risk classes** (passive / low-impact / active),
and **hash-verified evidence** for each provider run.

There is also a fully offline **Synthetic Recon** chain so you can explore the
whole pipeline without scanning anything real.

## Key features

- **Workspaces** with isolated SQLite storage outside the source tree
- **Target classification** (domain, URL, IP, CIDR, email, username, …) with IDNA
- **Asset graph**: domains, subdomains, IPs, ports, services, websites, technologies
- **Scope engine**: exact hosts, wildcards, CIDR, IPv4/IPv6, redirect-aware, per-IP
- **Providers**: Synthetic, Subfinder, native DNS, Nmap, HTTPX (see status matrix)
- **Evidence-first**: raw tool output preserved and SHA-256 verified before parsing
- **Durable events** with replay; **provenance** on every observation
- **Safe execution**: shell-free process supervision, timeouts, bounded output,
  process-group cancellation
- **No telemetry.** Network traffic happens only when you launch a provider.

See the full, honest [feature status matrix](docs/features.md) — several advanced
modules (web crawling, content discovery, vulnerability assessment, OSINT,
reporting) are **PLANNED**, not implemented, and are labeled as such.

## Architecture

```
SwiftUI app (MACSPLOIT / MACSPLOITKit)
        ↕  line-delimited JSON over pipes
Rust core (macsploit-core helper)
        ↕
SQLite (per-workspace)   +   Provider architecture (process supervisor / native)
```

- **SwiftUI** owns presentation only — it never parses provider output.
- **Rust core** owns domain logic: classification, scope, the asset graph, task/
  chain state, provider execution, evidence, and persistence.
- Details: [architecture](docs/architecture.md), [providers](docs/providers.md),
  [recon chains](docs/recon-chain.md), [security model](docs/security-model.md),
  [threat model](docs/threat-model.md).

## Supported platforms

- **macOS 13+** (developed and tested on macOS 26, Apple Silicon).
- Apple Silicon is the primary target; Intel is expected to work from source but is
  not yet routinely verified.
- Toolchain: Swift 6+ (Xcode or Command Line Tools) and Rust (stable).

## Build from source

```sh
git clone https://github.com/doctordoomies/MACSPLOIT.git
cd MACSPLOIT
./scripts/setup-hooks.sh     # optional: local commit/push safety hooks
./scripts/build-core.sh      # Rust core + helper
./scripts/test.sh            # Rust + Swift + policy tests (all offline)
./scripts/build-macos.sh     # ad-hoc-signed build/MACSPLOIT.app
./scripts/run.sh             # build and launch
```

The app is an **ad-hoc-signed local development build** — not notarized. macOS
Gatekeeper will warn on first launch; right-click → Open, or clear the quarantine
attribute, to run a build you compiled yourself.

## Quick start (no scanning required)

1. Launch MACSPLOIT.
2. Create a workspace **Test Assessment** with scope `example.test`,
   `*.example.test`, `192.0.2.0/24`.
3. Add the target `example.test`.
4. Run **Synthetic Recon** — a fully offline chain that exercises the real
   orchestration, persistence, evidence, and event pipeline with invented data.
5. Inspect the assets, relationships, and evidence; quit and reopen to see it
   persist.

## External tool requirements

Real recon needs the corresponding tools installed (MACSPLOIT **never installs
them for you** and shows each one's status):

| Provider | Tool | Install |
| --- | --- | --- |
| Subfinder | `subfinder` | `brew install subfinder` |
| Native DNS | *(built-in)* | — |
| Nmap | `nmap` | `brew install nmap` |
| HTTPX | `httpx` | `brew install httpx` (ProjectDiscovery) |

## Authorized use

MACSPLOIT is for systems you **own or are explicitly authorized to assess**. Its
scope engine is a technical control to help you stay within authorization —
targets and resolved IPs outside your configured scope are not actively scanned.
You are responsible for the legality of your engagements.

## Feature status & roadmap

See [docs/features.md](docs/features.md) for the authoritative status of every
capability and [docs/roadmap.md](docs/roadmap.md) for what's next (HTTPX web-recon
depth, TLS analysis, vulnerability assessment, OSINT, and reporting).

## Contributing

Contributions are welcome — especially new providers. Start with
[CONTRIBUTING.md](CONTRIBUTING.md) and the
[provider development guide](docs/provider-development.md). All automated tests for
security tools must be **offline** (fake executables / fixtures); never commit real
target data or secrets.

## Reporting security issues

Please report vulnerabilities **in MACSPLOIT itself** privately — see
[SECURITY.md](SECURITY.md). Do not open public issues for undisclosed
vulnerabilities.

## License

Licensed under the [Apache License 2.0](LICENSE).
