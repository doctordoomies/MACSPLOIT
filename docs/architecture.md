# Architecture foundation

Status: proposed architecture; application implementation has not begun.

## Components and ownership

The SwiftUI app owns presentation, navigation, analyst interactions, and native
macOS integration. Rust owns target normalization, workspace state, asset and
relationship invariants, provider scheduling, subprocess supervision, parser
boundaries, findings, and event production. Provider adapters own their metadata,
command construction, structured-output parsing, and normalized discoveries.
SQLite is the durable workspace index; evidence files remain outside the checkout.

The UI consumes normalized entities and events. It never parses scanner stdout
or implements scanner-specific scheduling. A scanner is replaceable without
changing the central asset model.

## Planned Rust workspace and Swift app

Phase 0 will add a root Cargo workspace with `core/` as its first crate. Keep
domain modules within that crate until there is a demonstrated boundary that
requires separate crates. Commit the application's Cargo lockfile.

`apps/macos/` will contain the SwiftUI application, presentation state, core
client, resources, and app-level tests. Use native navigation and inspector
controls, Apple Silicon as the primary target, and background event handling to
keep scanner activity off the UI thread. Keep shared Xcode project settings in
Git and personal Xcode state out of Git.

## Swift ↔ Rust boundary: decision pending

The first implementation must compare UniFFI, a small C ABI, and local IPC with
current upstream and Apple documentation. Record the selected approach and a
buildable proof before implementing broad domain functionality.

Local IPC is the initial candidate because the process supervisor must retain
results when the UI closes. A local per-user service could own database writes,
providers, and event replay while SwiftUI reconnects. This requires explicit
lifecycle, peer-access, versioning, and recovery design. An in-process bridge
still needs a separate lifecycle solution for durable scanner work. Do not open
a network listener or freeze a public ABI during repository setup.

## Persistence and events

Use one independent workspace store with migrations from its first version.
Proposed entities are workspaces, scope entries, targets, assets, relationships,
providers, provider runs, tasks, Recon Chain runs/stages, findings, evidence,
finding-evidence links, notes, reports, and audit events.

Every discovery records its source asset, provider run, observation time, and
confidence. Write entity changes and their durable event records in one
transaction. Events have a schema version, workspace ID, monotonically ordered
sequence, timestamp, kind, and typed payload. Clients resume from a sequence;
bounded buffers and resynchronization prevent slow clients from blocking work.

Initial event kinds include AssetDiscovered, RelationshipCreated,
ProviderStarted, ProviderCompleted, FindingCreated, EvidenceCreated, and
TaskStatusChanged. Snapshots and replay must agree after reconnect or restart.

## Execution and trust boundaries

All providers use one supervisor. It records executable path, argument array,
provider/version, target, PID, timestamps, stdout/stderr references, status, and
exit code. Preserve original output before parsing. Apply explicit concurrency,
per-host, request, size, depth, and runtime budgets; cancellation reaches child
processes. Failed parsers or individual providers must not destroy a chain.

Scope and risk checks occur before dispatch and at newly discovered targets or
redirects. Parser output is untrusted and must pass schema and workspace checks
before becoming durable state. Secret-shaped values are never treated as verified
credentials solely because they match a pattern.

## Decisions required before the first app slice

- Minimum macOS, Swift, Rust, and dependency versions, with reproducible builds.
- A tested communication boundary and service lifecycle.
- Schema version 1, migrations, uniqueness rules, and recovery semantics.
- App Sandbox, subprocess, distribution, and helper constraints, researched
  against current Apple guidance. No broad root requirement or automatic elevation.
- Boundaries for raw evidence, redacted UI/log views, and future report exports.

See [assets](assets.md), [providers](providers.md), [Recon Chains](recon-chain.md),
and [security](security-model.md) for the initial contracts.
