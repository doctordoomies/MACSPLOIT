# Architecture

Status: **IMPLEMENTED** Phase 0 foundation plus Phase 1A (Subfinder), Phase 1B
(native DNS resolution), and Phase 1C (Nmap port/service discovery); full on-screen
UI acceptance pending.

## Ownership

SwiftUI owns presentation, navigation, analyst actions, and native integration.
`MACSPLOITKit` contains Codable models, the core client, pipe transport, and a
main-actor workspace view model. Views do not parse provider output or write the
database. All blocking pipe/process operations run on a dedicated serial queue.

The root Cargo workspace contains one `macsploit-core` crate. Its library owns
target classification, workspace and asset invariants, scope, provider contracts,
Recon Chain execution, evidence, events, and storage. Its executable exposes that
library to Swift. Modules remain in one crate until a real extraction boundary
emerges. Cargo.lock pins dependencies; SQLite is bundled by rusqlite.

## Swift ↔ Rust

[ADR 0001](adr/0001-swift-rust-boundary.md) compares UniFFI, a C ABI, and IPC.
Phase 0 uses a bundled app-owned helper with anonymous stdin/stdout pipes and
versioned newline JSON. Requests have correlation IDs; responses contain typed
results or structured errors. Foundation Process receives an executable URL and
an argument array. There is no shell or network listener.

A worker thread executes the chain while the command loop serves UI reads and
cancellation. Swift polls committed events every 250 ms using the last snapshot
sequence. On new events it refreshes a consistent snapshot. A reconnect reloads
persisted state. The [protocol](../schemas/internal-protocol-v1.md) bounds frames
and documents error handling. Integration tests exercise the actual helper.

## Storage and replay

Each workspace has its own migrated SQLite database and evidence directory:

```text
~/Library/Application Support/MACSPLOIT/
├── core.lock
├── logs/application.jsonl
└── workspaces/<uuid>/
    ├── workspace.sqlite
    └── evidence/<uuid>.json
```

The core rejects storage inside a Git checkout. UUIDs identify externally visible
objects. Migration 001 creates domain, orchestration, evidence, provenance, event,
and audit tables. Connections enable foreign keys and a busy timeout; workspace
creation selects WAL. Composite keys enforce workspace ownership.

Discovery transactions write assets, relationships, observations, and events
together. Original output is hashed and committed before parsing. A crash between
file creation and its database insert can leave an unreferenced evidence file;
there is no cleanup/retention UI yet. Filesystem writes and SQLite cannot form one
transaction. No incomplete normalized discovery transaction becomes visible.

Events have UUID, workspace, monotonic sequence, timestamp, type, and JSON payload.
Replay returns up to 256 events strictly after a cursor. Snapshots contain a
consistent graph and the latest 1,000 events plus current sequence. The UI renders
that recent window; older events remain queryable through replay.

## Lifecycle and constraints

An exclusive lock permits one core per storage root. Closing the app's pipes
cancels bounded synthetic work. Startup marks interrupted pending/running chains
FAILED with `Interrupted` and emits recovery events; it never resumes scanning.
Completed results survive process and application restarts at the storage layer.
Full on-screen restart verification remains pending, as recorded in the test report.

## Providers and DNS decision

Providers implement one Rust trait (metadata/installation/execute/parse, plus an
optional per-provider timeout) and are selected by capability, or pinned per chain
stage when a capability has more than one provider. Four are registered: the offline
synthetic provider, Subfinder (passive external tool), native DNS (built-in), and
Nmap (active external tool). A pinned provider is trusted to operate on the chain's
input assets, so provider selection by id is validated on capability only — the
chain target type is not re-checked (Nmap consumes IPAddress assets while the chain
target is a Domain).

**Nmap (Phase 1C).** The first ACTIVE provider. It runs the external Nmap tool
through the process supervisor with a conservative, unprivileged profile
(`-sT -sV --top-ports 100 -oX -`, no NSE, no root), parses XML with `roxmltree`, and
produces Port/Service assets with `exposes`/`serves` relationships. It has a longer
per-provider timeout (120 s) than passive providers; scope is re-checked per IP so an
out-of-scope resolved address is never scanned. Launching a Recon Chain is the
analyst's explicit approval for its active stages.

**Native DNS (Phase 1B).** DNS resolution is implemented in Rust with
`hickory-resolver` (pulling `tokio` for a current-thread runtime) rather than an
external CLI such as `dnsx`. Rationale: ordinary resolution should work with no
install step; native code gives simpler offline tests, lower overhead, normalized
A/AAAA results, clear per-host outcome classification, and a base capability even
if an external DNS provider is added later. Resolution sits behind an injectable
`DnsResolver` trait (system-config-based production resolver; static offline
resolver for tests), so the orchestrator stays synchronous and the async runtime is
contained inside the provider. The system resolver configuration is used by default;
no public resolver is hardcoded.

**Process supervision (Phase 1A).** External tools run under a centralized
supervisor with bounded stdout/stderr, exit code capture, a deadline, and
process-group cancellation. Per-host/request limits and a dedicated per-provider
timeout remain **PLANNED**.

**FUTURE:** a per-user service that survives full UI quit, with peer authorization
and lifecycle/version negotiation. The internal protocol and durable entities can
be reused; Phase 0 does not claim daemon behavior or a public plugin ABI. Findings,
reporting, distribution, sandboxing/notarization, and hardware are also deferred.
