# Architecture

Status: **IMPLEMENTED** Phase 0 foundation; full native UI acceptance pending.

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

**PLANNED:** external process supervision with bounded stdout/stderr, exit code,
process-group cancellation, per-host/request limits, and explicit tool lifecycle.
The current provider runs internally and has no child scanner processes.

**FUTURE:** a per-user service that survives full UI quit, with peer authorization
and lifecycle/version negotiation. The internal protocol and durable entities can
be reused; Phase 0 does not claim daemon behavior or a public plugin ABI. Findings,
reporting, distribution, sandboxing/notarization, and hardware are also deferred.
