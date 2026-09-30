# Recon Chain execution

Status: **IMPLEMENTED** two chain presets — the offline Synthetic Recon chain and
the real Domain Recon chain (Subfinder + native DNS resolution).

A chain requests provider capabilities and feeds scoped discoveries into later
stages. It is not a shell sequence of installed tools. A stage may pin an exact
provider so a capability offered by more than one provider is unambiguous. The
stage plans are fixed presets; a general dependency-graph scheduler remains planned.
`start_chain` selects the preset by a `chain` argument (`synthetic` by default, or
`domain_recon`); the analyst chooses and launches a chain explicitly — adding a
target never starts one.

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

## Domain Recon (Phase 1A + 1B)

The first real chain runs Subfinder and then native DNS resolution against an
in-scope domain. Its stages are:

1. Target Validation — require a Domain target inside workspace scope.
2. Subfinder Discovery — request SUBDOMAIN_DISCOVERY, pinned to the `subfinder`
   provider, executed through the process supervisor.
3. DNS Resolution — request DNS_RESOLUTION, pinned to the `native_dns` provider,
   resolving the Subdomain/Hostname/Domain assets from earlier stages into IPs.
4. Persistence — assets, relationships, observations, and evidence are committed.
5. Completion — persist final status.

Ports and HTTP are intentionally absent; Domain Recon maps a Domain to Subdomains
to IP addresses:

```text
example.test
├── api.example.test  → resolves_to → 192.0.2.10
├── dev.example.test  → resolves_to → 192.0.2.11
└── auth.example.test → resolves_to → 192.0.2.12
```

Each discovered subdomain and resolved IP is traceable to its target, provider run,
provider version, timestamp, source asset, evidence, and scope decision
(`in_scope`). If Subfinder is missing the chain fails with `ProviderMissing`; if a
provider exits non-zero or times out the run is marked FAILED with its evidence
preserved. DNS "no records"/NXDOMAIN for a host is not a chain failure. Automated
tests drive this chain entirely offline through a fake executable and a static DNS
resolver — no real scanning or DNS queries.

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
budget. The synthetic provider is immediate and bounded. External providers run through
the process supervisor: an argument array (never a shell), bounded stdout/stderr
(512 KiB / 64 KiB), a wall-clock deadline within the chain budget, and cancellation
that kills the whole child process group so a killed tool leaves no orphans. The
native DNS provider runs in-process with a bounded per-query timeout (default 5 s)
and bounded concurrency (default 16), still inside the chain deadline and honoring
cancellation. A dedicated per-provider timeout (beyond the 30-second chain budget)
is planned.

On shutdown the core asks work to cancel. On abnormal interruption, reopening
marks pending/running work FAILED with `Interrupted`; it never automatically
restarts it. Completed graph, evidence, provenance, events, and history survive
restart in the automated tests.

**PLANNED:** Nmap then HTTPX providers, a dedicated per-provider timeout, per-host
and request limits, dependency scheduling, explicit retry policy, DNS
freshness/caching, and HTTP/redirect scope rechecks. **FUTURE:** a separately
managed core service that continues while the UI application is fully quit. The
helper is app-owned.
