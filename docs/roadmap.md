# Roadmap

Repository setup is complete. Phase 0 code is implemented and its automated
checks pass; the remaining native UI walkthrough/restart check is blocked by the
UI automation connection, so final foundation acceptance is pending. Phase 1
and later phases remain planned. See [verification](phase-0-verification.md).

| Phase | Scope | Exit condition |
| --- | --- | --- |
| Repository setup | Private remote, ignore policy, documentation, commit/push guards | Reviewed initial commit pushed to the verified private repository |
| 0 — Foundation | SwiftUI, Rust, communication, SQLite, workspaces, assets, events, providers, tasks, logs | Offline synthetic provider completes a durable end-to-end app workflow |
| 1 — First Recon Chain | Domain input, subdomains, DNS, ports/services, HTTP, interactive graph | Subfinder, Nmap, and HTTPX adapters work incrementally within explicit scope |
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

Complete the blocked Phase 0 GUI acceptance check, then begin Phase 1 with a
Subfinder structured-output parser and synthetic fixtures. Add supervised,
explicitly authorized execution only after timeout, cancellation, output bounds,
and scope tests pass. Introduce Nmap and HTTPX independently afterward.
