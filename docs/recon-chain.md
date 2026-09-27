# Recon Chain execution model

Status: planned design; no network operations are implemented.

A Recon Chain is a durable dependency graph of capability requests. It reacts
to discoveries and applies scope and budgets before scheduling more work. It
must not be a sequential shell script that runs every installed tool.

For the first real chain: classify a domain, discover subdomains, resolve hosts,
discover ports and services on allowed addresses, probe applicable HTTP services,
and populate the asset graph with provenance. A discovered third-party address
or redirect stays visible but does not automatically receive active work.

Tasks move from QUEUED to RUNNING, then COMPLETED, FAILED, or CANCELLED. PAUSED
must have documented cooperative semantics before appearing in the UI; do not
promise arbitrary safe subprocess suspension. A retry creates an auditable
attempt and requires a policy appropriate to the provider's impact. Active
scans are not automatically retried indiscriminately.

The scheduler enforces global, provider, per-host, and HTTP-request limits.
Chain budgets bound discovery depth, unique assets, requests, and elapsed time.
Use stable work identities to suppress duplicate tasks; cached data must retain
freshness and provenance. Pause dispatch when budgets are exhausted and expose
the reason in the activity stream.

Provider failure marks affected work and dependent stages appropriately while
unrelated stages continue. Cancellation stops queued work and reaches running
process groups. Persist status transitions, output references, and errors so
UI closure does not discard results. Recovery must distinguish interrupted work
from completed work and must not restart active scanning without policy review.

The first acceptance scenario is offline: a synthetic provider discovers
`api.example.test`, `192.0.2.10`, and HTTPS on TCP 443. SwiftUI displays linked
assets and provenance persisted by Rust in SQLite. Repeat runs must deduplicate
correctly, and reopening the workspace must recover the same graph.
