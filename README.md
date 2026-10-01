<table>
<tr>
<td width="60%" valign="middle">

<h1>MACSPLOIT</h1>

<h3>Native macOS security reconnaissance, crawling, correlation, and evidence — in one workspace.</h3>

<p>
  <strong>SwiftUI frontend · Rust core · SQLite persistence · Modular providers</strong>
</p>

<p>
  <a href="https://github.com/doctordoomies/MACSPLOIT/actions"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/doctordoomies/MACSPLOIT/ci.yml?branch=main&style=for-the-badge&label=BUILD"></a>
  <a href="https://github.com/doctordoomies/MACSPLOIT/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/github/license/doctordoomies/MACSPLOIT?style=for-the-badge&label=LICENSE"></a>
  <img alt="macOS" src="https://img.shields.io/badge/macOS-13%2B-black?style=for-the-badge&logo=apple">
  <img alt="Rust" src="https://img.shields.io/badge/core-Rust-black?style=for-the-badge&logo=rust">
  <img alt="Swift" src="https://img.shields.io/badge/UI-SwiftUI-black?style=for-the-badge&logo=swift">
</p>

<p><strong>v0.1 public beta</strong> · Domain Recon · Web Recon · Asset Graph · Evidence</p>

<p><sub>Pre-1.0 APIs and provider contracts may change.</sub></p>

</td>
<td width="40%" align="right" valign="top">
  <img src="assets/Neon%20Rain%20Hacker%20Workspace.png" alt="MACSPLOIT neon security workstation artwork" width="380">
</td>
</tr>
</table>
---

<table>
<tr>
<td width="58%" valign="top">

## One workspace. One asset graph. Every layer of the investigation.

MACSPLOIT turns separate reconnaissance tools into a single **persistent security workspace**.

Instead of juggling terminal output, every discovery becomes a normalized asset with:

- **provenance** — where it came from
- **evidence** — the raw provider result that produced it
- **relationships** — how assets connect
- **scope state** — whether active work is allowed
- **durable history** — persisted events and provider runs

MACSPLOIT is built for **authorized security research** and runs locally with **no telemetry**.

</td>
<td width="42%" valign="top">

### Real recon workflows

**Domain Recon**

```text
Domain
  ↓ Subfinder
Subdomain
  ↓ Native DNS
IPAddress
  ↓ Nmap
Port / Service
  ↓ HTTPX
Website / Technology
```

**Web Recon**

```text
HTTP(S) URL
  ↓ Katana
URL assets
```

**Web Analysis**

```text
HTTP(S) URL
  ↓ Native HTTP Analysis
headers · cookies · CORS · redirects · robots
```

</td>
</tr>
</table>

---

## Why MACSPLOIT?

<table>
<tr>
<td width="33%" valign="top">

### ◈ Asset-first

Provider output is not the product.

MACSPLOIT normalizes discoveries into durable assets and relationships so your investigation survives beyond one terminal session.

</td>
<td width="33%" valign="top">

### ◈ Evidence-first

Every provider run preserves its raw evidence before parsing.

Evidence is SHA-256 verified and linked back to the assets it produced.

</td>
<td width="33%" valign="top">

### ◈ Scope-first

Passive, low-impact, and active providers are treated differently.

Out-of-scope discoveries do **not** silently become active scan targets.

</td>
</tr>
</table>

---

## Recon pipeline

```mermaid
flowchart LR
    subgraph Domain_Recon[Domain Recon]
        A[Domain] -->|Subfinder| B[Subdomain]
        B -->|Native DNS| C[IPAddress]
        C -->|Nmap| D[Port / Service]
        D -->|HTTPX| E[Website / Technology]
    end

    subgraph Web_Recon[Web Recon]
        U[HTTP(S) URL] -->|Katana| V[URL assets]
    end

    subgraph Web_Analysis[Web Analysis]
        W[HTTP(S) URL] -->|Native HTTP Analysis| X[Headers / Cookies / CORS / Redirects / robots]
    end

    E --> G[Evidence + Events + Asset Graph]
    V --> G
    X --> G
```

Every stage is implemented as a provider capability. Results flow through:

```text
provider
   ↓
supervised execution / native capability
   ↓
raw evidence
   ↓
parser
   ↓
normalization
   ↓
scope checks
   ↓
assets + relationships
   ↓
SQLite + durable events
   ↓
SwiftUI
```

---

## Highlights

| | Capability | What it means |
|---|---|---|
| ◉ | **Persistent workspaces** | Each assessment has isolated SQLite-backed state outside the repo |
| ◉ | **Target classification** | Domain, URL, IP, CIDR, email, username, and more |
| ◉ | **Asset graph** | Domains, subdomains, IPs, ports, services, websites, URLs, technologies |
| ◉ | **Scope engine** | Exact hosts, wildcards, CIDR, IPv4/IPv6, redirect-aware decisions |
| ◉ | **Modular providers** | Synthetic, Subfinder, Native DNS, Nmap, HTTPX, Katana, Native HTTP Analysis |
| ◉ | **Web Recon** | Bounded same-host Katana crawling from an explicitly selected in-scope URL |
| ◉ | **Evidence + provenance** | Raw provider output preserved and tied to every observation |
| ◉ | **Durable events** | Replayable activity history across application restarts |
| ◉ | **Safe execution** | Shell-free process supervision, timeouts, bounded output, cancellation |
| ◉ | **Offline demo** | Explore the full orchestration path with `example.test` |
| ◉ | **No telemetry** | Network activity occurs only when you explicitly launch a provider |

> The [feature matrix](docs/features.md) is the authoritative source for what is **stable**, **beta**, **planned**, and **future**.

---

## Architecture

<table>
<tr>
<td width="50%" valign="top">

### macOS app

**SwiftUI / MACSPLOITKit**

Owns:
- navigation
- workspace UX
- recon controls
- asset inspection
- evidence and activity views

It does **not** parse security-tool output.

</td>
<td width="50%" valign="top">

### Core

**Rust / macsploit-core**

Owns:
- classification
- scope
- asset relationships
- Recon Chains
- provider execution
- evidence
- events
- SQLite persistence

</td>
</tr>
</table>

```text
┌─────────────────────────────┐
│        SwiftUI App          │
│  workspace · recon · views  │
└──────────────┬──────────────┘
               │ line-delimited JSON
               ▼
┌─────────────────────────────┐
│          Rust Core          │
│ assets · scope · providers  │
└───────┬─────────────┬───────┘
        │             │
        ▼             ▼
   ┌─────────┐   ┌──────────────┐
   │ SQLite  │   │   Providers  │
   └─────────┘   │ native / CLI │
                 └──────────────┘
```

Read more:
[Architecture](docs/architecture.md) ·
[Providers](docs/providers.md) ·
[Recon Chains](docs/recon-chain.md) ·
[Security Model](docs/security-model.md) ·
[Threat Model](docs/threat-model.md)

---

## Try it without scanning anything

MACSPLOIT ships with a **fully offline Synthetic Recon chain**.

```text
Workspace: Test Assessment
Target:    example.test
Scope:     example.test
           *.example.test
           192.0.2.0/24
```

1. Launch MACSPLOIT.
2. Create **Test Assessment**.
3. Add `example.test`.
4. Open **Recon**.
5. Run **Synthetic Recon**.
6. Inspect **Assets**, **Evidence**, and **Activity**.
7. Quit and reopen the app — the workspace persists.

The synthetic path exercises the real orchestration, normalization, evidence, persistence, and event systems using invented data only.

---

## Build from source

### Requirements

- **macOS 13+**
- Swift 6+ via Xcode or Command Line Tools
- Rust stable
- Git
- Python 3.10+

Apple Silicon is the primary verified target. Intel macOS is expected to work from source but is not routinely verified yet.

### Build

```sh
git clone https://github.com/doctordoomies/MACSPLOIT.git
cd MACSPLOIT

./scripts/setup-hooks.sh
./scripts/test.sh
./scripts/build-macos.sh
./scripts/run.sh
```

The development app is currently **ad-hoc signed**, not notarized.

---

## Real provider requirements

MACSPLOIT detects external tools but **never silently installs them**.

| Provider | Type | Requirement | Risk |
|---|---|---|---|
| **Subfinder** | External | `brew install subfinder` | Passive |
| **Native DNS** | Built in | None | Active · Low Impact |
| **Nmap** | External | `brew install nmap` | Active |
| **HTTPX** | External | `brew install httpx` | Active · Low Impact |
| **Katana** | External | `brew install katana` | Active · Low Impact |
| **Native HTTP Analysis** | Built in | None | Active · Low Impact |

Tool availability, provider version, and risk are surfaced in the application.

---

## Safety model

MACSPLOIT is intended for systems you **own or are explicitly authorized to assess**.

A discovered asset is not automatically permission to scan it.

For example:

```text
in-scope domain
      ↓
resolved IP
      ↓
scope re-check
      ↓
active provider allowed / denied
```

This matters for shared infrastructure, redirects, third-party services, and cloud-hosted targets.

Read the full [security model](docs/security-model.md).

---

## Project status

MACSPLOIT is currently a **public beta**.

### Implemented

`Synthetic Recon` · `Domain Recon` · `Web Recon` · `Web Analysis` · `Subfinder` · `Native DNS` · `Nmap` · `HTTPX` · `Katana` · `Asset Graph` · `Evidence` · `Scope` · `Durable Events`

### Planned

`Content Discovery` · `Historical URLs` · `JavaScript Analysis` · `TLS Analysis` · `Findings` · `Reporting` · `OSINT` · `Tool Manager`

### Future

`Wireless` · `Hardware` · `SDR` · `Bluetooth` · `Authorized Validation / Lab Mode`

See [docs/features.md](docs/features.md) and [docs/roadmap.md](docs/roadmap.md).

---

## Contributing

Contributions are welcome — especially new providers and improvements to the core workspace model.

Start with:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [Provider development guide](docs/provider-development.md)
- [Security model](docs/security-model.md)

All automated security-tool tests must remain **offline** using fake executables, fixtures, or synthetic data.

Never commit real assessment data or secrets.

---

## Security

Found a vulnerability **in MACSPLOIT itself**?

Please report it privately using the process in [SECURITY.md](SECURITY.md).

Do **not** open a public issue for an undisclosed security vulnerability.

---

## License

MACSPLOIT is licensed under the [Apache License 2.0](LICENSE).

---

<div align="center">

### MACSPLOIT

**One workspace. One asset graph. Every layer of the investigation.**

<sub>Built for authorized security research on macOS.</sub>

</div>
