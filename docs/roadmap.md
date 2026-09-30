# Roadmap

Repository setup and Phase 0 are implemented with passing automated checks; the
native UI walkthrough/restart check remains blocked by the UI automation connection.
**Phase 1A, 1B, and 1C are implemented:** Subfinder (passive external), native DNS
(built-in), and Nmap (active external) plug into the provider architecture behind a
`Domain Recon` chain (Subfinder → DNS Resolution → Port + Service Discovery), with
offline tests. HTTPX remains planned. See [verification](phase-0-verification.md),
[providers](providers.md), and [recon-chain](recon-chain.md).

| Phase | Scope | Exit condition |
| --- | --- | --- |
| Repository setup | Private remote, ignore policy, documentation, commit/push guards | Reviewed initial commit pushed to the verified private repository |
| 0 — Foundation | SwiftUI, Rust, communication, SQLite, workspaces, assets, events, providers, tasks, logs | Offline synthetic provider completes a durable end-to-end app workflow |
| 1 — First Recon Chain | Domain input, subdomains, DNS, ports/services, HTTP, interactive graph | Subfinder, Nmap, and HTTPX adapters work incrementally within explicit scope (1A: Subfinder — done; 1B: native DNS — done; 1C: Nmap — done) |
| 2 — Web reconnaissance | Crawling, content discovery, native analyzers, technology, screenshots, historical URLs | Findings and assets retain evidence and provenance |
| 3 — Vulnerability assessment | Nuclei, TLS, conservative integrations, correlation | Evidence-backed findings with distinct severity and confidence |
| 4 — OSINT | Username, email, and phone providers | Confidence and provenance preserved without treating uncertain matches as identity proof |
| 5 — Reporting | JSON, Markdown, HTML; PDF later | Versioned exports with reviewed private-data handling |
| 6 — Provider SDK | Stable internal contracts then third-party tooling | Documented and tested plugin boundary |
| 7 — Authorized validation / lab | Separate opt-in validation layer | Explicit authorization and isolation from standard reconnaissance |
| 8 — Hardware and wireless | Future management and authorized lab modules | Scope and permission design reviewed before implementation |

Do not add an LLM dependency, dozens of providers, broad cloud enumeration,
traffic interception, wireless attacks, or a public plugin ABI during Phase 0.
Distribution, signing, notarization, and final branding come later; publishing
releases or changing repository visibility still requires explicit approval.

## Next starting point

Phase 1A (Subfinder), 1B (native DNS), and 1C (Nmap) are complete. The next step is
**Phase 1D — HTTPX** (HTTP/HTTPS probing of discovered web services), introduced
independently and only after its timeout, cancellation, output-bound, and scope tests
pass. The blocked Phase 0 GUI acceptance walkthrough still remains to be performed
when reliable native UI automation is available.
