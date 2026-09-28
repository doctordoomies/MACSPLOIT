# Recon Chain execution

Status: **IMPLEMENTED** one durable offline Synthetic Recon chain.

The chain requests provider capabilities and feeds scoped discoveries into later
stages. It is not a shell sequence of installed tools. The initial stage plan is
fixed; a general dependency-graph scheduler remains planned.

## Implemented workflow

1. Target Processing — require the stored `example.test` Domain in workspace scope.
2. Synthetic Subdomain Discovery — request SUBDOMAIN_DISCOVERY.
3. Synthetic Resolution — request DNS_RESOLUTION for scoped current-run assets.
4. Synthetic Service Discovery — request SERVICE_FINGERPRINTING for scoped IPs.
5. Completion — persist final status.

With scope `example.test`, `*.example.test`, and `192.0.2.0/24`, the first run creates:

```text
example.test
├── api.example.test
│   └── 192.0.2.10
│       └── tcp/443 → HTTPS
└── dev.example.test
    └── 192.0.2.11
        ├── tcp/22  → SSH
        └── tcp/443 → HTTPS
```

This is 11 assets, 10 relationships, 3 provider executions, and 3 JSON evidence
records. Repeat runs keep node/edge IDs and add provenance, run records, and
evidence. Passive out-of-scope discoveries remain visible with `in_scope=false`
but are excluded from downstream dispatch. An unscoped root cannot start.

## State and events

Tasks/stages support QUEUED, RUNNING, PAUSED, COMPLETED, FAILED, CANCELLED.
Validated normal transitions go QUEUED → RUNNING → terminal. PAUSED exists in the
model but has no control or implemented suspension behavior. Chains support
PENDING, RUNNING, COMPLETED, PARTIAL, FAILED, CANCELLED; PARTIAL is reserved.
A provider failure ends this simple chain FAILED and preserves completed work.
Independent-branch continuation/retry requires the future graph scheduler.

State changes emit durable events. SwiftUI polls after its committed cursor and
refreshes snapshots during execution. A small per-stage synthetic delay makes
progress visible without blocking the UI actor. The worker checks cancellation
between stages and around provider execution; cancelled queued/running work and
user audit records are durable.

Implemented limits: one active chain globally, 100 targets and 100 chain runs per
workspace, 1,000 assets, 1 MiB evidence per run, and a 30-second cooperative chain
budget. The synthetic provider is immediate and bounded. These limits are not a
subprocess runtime enforcement mechanism.

On shutdown the core asks work to cancel. On abnormal interruption, reopening
marks pending/running work FAILED with `Interrupted`; it never automatically
restarts it. Completed graph, evidence, provenance, events, and history survive
restart in the automated tests.

**PLANNED:** real adapters, process cancellation/timeouts, per-host and request
limits, dependency scheduling, explicit retry policy, freshness/caching, and
HTTP/redirect scope rechecks. **FUTURE:** a separately managed core service that
continues while the UI application is fully quit. The Phase 0 helper is app-owned.
