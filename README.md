# MACSPLOIT

**Active private development.** The canonical repository is
[doctordoomies/MACSPLOIT](https://github.com/doctordoomies/MACSPLOIT) and must remain
PRIVATE. Origin: `https://github.com/doctordoomies/MACSPLOIT.git`.

MACSPLOIT is a native macOS modular cybersecurity workbench for authorized
security research. Targets, discoveries, relationships, and evidence belong to
an independent workspace model; providers supply observations about that model.

## Current status

**IMPLEMENTED — Phase 0 foundation:** a runnable SwiftUI application communicates
with a bundled Rust helper, persists workspaces in SQLite, and runs an entirely
offline synthetic Recon Chain. `example.test` produces two subdomains, two
documentation IP addresses, three ports, and three services, with provenance,
SHA-256 evidence, durable events, and replay. No scanner is installed or invoked.

The macOS bundle builds and launches. Rust and Swift integration tests verify
execution and persisted state after restarting the core. Workspace creation was
also verified through the UI. The remaining on-screen workflow and full GUI
quit/reopen check are **blocked by the native UI automation connection**; that GUI
acceptance check remains open. See
[verification](docs/phase-0-verification.md) for precise results and limitations.

**IMPLEMENTED — Phase 1A first real provider:** a `SubfinderProvider` runs the
external ProjectDiscovery `subfinder` tool through a centralized, shell-free process
supervisor to turn an in-scope domain into subdomains, with executable discovery,
installation/version detection, structured JSONL parsing, raw evidence, provenance,
scope enforcement, and durable events — plugged into the same provider architecture
as the synthetic provider, which is retained. A `Domain Recon` chain and its UI are
wired up. MACSPLOIT never installs Subfinder; automated tests run entirely offline
against a fake executable. **PLANNED next:** DNS resolution, then Nmap, then HTTPX.
See [providers](docs/providers.md) and [recon-chain](docs/recon-chain.md).

## Build and run

Requires macOS, Apple Command Line Tools or Xcode with Swift 6+, Rust 1.90+,
Git, Python 3.10+, and authenticated GitHub CLI for private pushes. The verified
machine uses Apple Silicon, macOS 26, Swift 6.3.2, and Rust 1.98.1.

```sh
./scripts/setup-hooks.sh
./scripts/test.sh
./scripts/run.sh
```

`run.sh` builds an ad-hoc signed `build/MACSPLOIT.app` and opens it. Dependencies
must already be available for an offline build; the application itself performs
no network requests. Scripts never install toolchains or scanner software.

Create **Test Assessment**, keep the suggested synthetic scope, add
`example.test`, and select **Recon → Run**. Inspect **Assets**, **Evidence**, and
**Activity**. Quit and reopen the app to check the saved workspace. Runtime data
lives in `~/Library/Application Support/MACSPLOIT/`, outside this checkout.

## Architecture

- `apps/macos/`: native SwiftUI app, typed core client, view models, and tests.
- `core/`: one Rust crate owning classification, scope, assets, orchestration,
  synthetic provider, evidence, events, migrations, and SQLite persistence.
- `providers/`: boundary reserved for later external adapters.
- `schemas/`: internal protocol documentation; no public plugin ABI.
- `fixtures/`: synthetic offline examples only.
- `tests/`: repository policy tests; core and app integration tests live beside code.
- `scripts/`: verified build/test/launch commands and repository safeguards.

Read the [boundary ADR](docs/adr/0001-swift-rust-boundary.md),
[architecture](docs/architecture.md), [development guide](docs/development.md),
[asset model](docs/assets.md), [providers](docs/providers.md), and
[Recon Chains](docs/recon-chain.md).

## Scope and privacy

**PLANNED — Phase 1:** incremental real providers after foundation acceptance,
starting with Subfinder fixtures and supervised execution, then Nmap and HTTPX.
**FUTURE:** graph visualization, findings, reporting, tool management, OSINT,
validation/lab, hardware, distribution, and publishing. See the unchanged phase
sequence in the [roadmap](docs/roadmap.md).

Use only systems you own or are authorized to assess. Discovered assets do not
automatically become active targets. Never commit credentials, private keys,
`.env` files, Keychain exports, real assessments, databases, or sensitive captures.
See [security](docs/security-model.md) and [repository policy](docs/repository-policy.md).
Every push must pass the existing history audit and exact private-destination
check. Collaborators, Pages, releases, and visibility changes require owner approval.
