# Recon Chain execution

Status: **IMPLEMENTED** six chain presets — offline **Synthetic Recon**; built-in
**DNS Recon**; the full **Domain Recon** (Subfinder → DNS → Nmap → HTTPX);
**Web Recon** (Katana crawl); **Web Analysis** (native HTTP analysis); and
**Content Discovery** (bounded ffuf path discovery).

A chain requests provider capabilities and feeds scoped discoveries into later
stages. It is not a shell sequence of installed tools. A stage may pin an exact
provider so a capability offered by more than one provider is unambiguous. The
stage plans are fixed presets; a general dependency-graph scheduler remains planned.
`start_chain` selects the preset by a `chain` argument (`synthetic` by default, or
`dns_recon`, `domain_recon`, `web_recon`, `web_analysis`, `content_discovery`); the
analyst chooses and launches a chain explicitly — adding a target never starts one.

The three web chains (**Web Recon**, **Web Analysis**, **Content Discovery**) accept an
explicitly scoped local or private URL target — `http://localhost:3000`,
`http://127.0.0.1:8080`, `http://[::1]:8080`, a private IP/CIDR host, or an `/etc/hosts`
dev name — with custom ports and no public-DNS prerequisite. Local/private status is not
authorization: the host must be in workspace scope, enforced by the core. Same-host
filtering is by hostname (port-agnostic); cross-host redirects and off-host crawl/ffuf
results stay fail-closed, and `localhost` / `127.0.0.1` / `::1` are distinct identities.

## Content Discovery (Phase 2C)

An explicit, bounded path-discovery chain over an in-scope HTTP(S) URL using ffuf
and a wordlist the analyst selects. Stages: Target Validation → Wordlist Validation →
Content Discovery (`ffuf`) → Persistence → Completion. Risk is **ACTIVE**; it never
runs as part of another chain. The wordlist path is passed as a typed `start_chain`
option (`{"wordlist_path": ...}`) and validated in the core (≤ 500 entries, ≤ 1 MiB,
≤ 512-byte lines, UTF-8; blanks and `#` comments ignored). ffuf runs with a bounded,
deterministic profile (top status codes, 10 threads, 10 req/s, 5 s per request, no
redirects, no recursion). Accepted results become same-host `URL` assets with
`has_endpoint` relationships from the root; 404s create no asset; raw output is hashed
evidence, and the persisted command redacts the local wordlist path to its file name.
Offline tests use a fake ffuf and a fixture wordlist — no network. Workspace scope
can be edited after creation, but the Rust core still authorizes the target at chain
creation and re-checks scoped assets before provider dispatch.

## DNS Recon

A built-in live workflow for an explicitly in-scope Domain or Hostname. It gives a
fresh installation a useful real reconnaissance path without requiring an external
CLI:

```text
Domain / Hostname
  → Native DNS Resolver (A + AAAA)
  → IPAddress assets + resolves_to relationships
  → Evidence
```

Stages: Target Validation → DNS Resolution (`native_dns`) → Persistence →
Completion. Risk is ACTIVE_LOW_IMPACT. Production resolution uses the host's system
resolver configuration; automated coverage injects `StaticDnsResolver` so CI never
performs live DNS. No external provider is installed or invoked.

## Web Analysis (Phase 2B)

A native, built-in chain (no external tool) over an explicitly selected in-scope
HTTP(S) URL:

```text
HTTP(S) URL
  → Native HTTP Analysis (native_http)
      ├── response + security headers (HSTS/CSP/XFO/XCTO/Referrer/Permissions)
      ├── cookie security flags (never values)
      ├── CORS headers
      ├── scope-checked redirect chain
      └── robots.txt
```

Stages: Target Validation → Native HTTP Analysis (`native_http`) → Persistence →
Completion. It is independent of Katana — Web Analysis runs even when Katana is not
installed. Risk is ACTIVE_LOW_IMPACT; every redirect hop is scope-checked, and the
full normalized report is stored as hashed evidence while the `Website` asset is
enriched via an observation. Offline tests use a static web transport; no network.

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

## Domain Recon (Phase 1A–1D)

The full chain runs Subfinder, native DNS resolution, Nmap, and HTTPX against
authorized in-scope discoveries from a Domain target. Its stages are:

1. Target Validation — require a Domain target inside workspace scope.
2. Subfinder Discovery — SUBDOMAIN_DISCOVERY, pinned to `subfinder`, via the
   process supervisor (PASSIVE).
3. DNS Resolution — DNS_RESOLUTION, pinned to `native_dns`, resolving the
   Subdomain/Hostname/Domain assets into IPs (ACTIVE_LOW_IMPACT).
4. Port + Service Discovery — PORT_DISCOVERY, pinned to `nmap`, scanning the
   in-scope IP assets for open ports and services (ACTIVE).
5. HTTP Probing — HTTP_PROBING, pinned to `httpx`, probing discovered in-scope
   web services into Website/Technology assets (ACTIVE_LOW_IMPACT).
6. Persistence — assets, relationships, observations, and evidence are committed.
7. Completion — persist final status.

Domain Recon maps Domain → Subdomains → IPs → Ports/Services → Websites/Technology:

```text
example.test
└── api.example.test  → resolves_to → 192.0.2.10
                                      ├── 22/tcp  → serves → ssh
                                      └── 443/tcp → serves → https
                                                    └── HTTPX → Website / Technology
```

Each asset is traceable to its target, provider run, provider version, timestamp,
source asset, evidence, and scope decision (`in_scope`). The Nmap stage scans only
in-scope IPs (an out-of-scope resolved IP is filtered out before the active tool
runs). If a required tool is missing the chain fails with `ProviderMissing` (earlier
stages' results are already persisted); if a provider exits non-zero or times out
the run is marked FAILED with its evidence preserved. DNS "no records"/NXDOMAIN, and
Nmap "host down"/"no open ports", are not chain failures. Automated tests drive this
chain entirely offline through fake executables and a static DNS resolver — no real
scanning, DNS, or port traffic.

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
workspace, 1,000 assets, 1 MiB evidence per run, per-provider timeouts (30 s default,
120 s for Nmap), and a 300-second overall chain-budget safety net. The synthetic
provider is immediate and bounded. External providers run through the process
supervisor: an argument array (never a shell), bounded stdout/stderr (512 KiB /
64 KiB), a per-provider deadline, and cancellation that kills the whole child process
group so a killed tool leaves no orphans. The native DNS provider runs in-process
with a bounded per-query timeout (default 5 s) and bounded concurrency (default 16).
Nmap runs at most two processes (one per IP family). Per-host/request limits remain
planned.

On shutdown the core asks work to cancel. On abnormal interruption, reopening
marks pending/running work FAILED with `Interrupted`; it never automatically
restarts it. Completed graph, evidence, provenance, events, and history survive
restart in the automated tests.

**PLANNED:** per-host and request limits, dependency scheduling, explicit retry
policy, and DNS freshness/caching. **FUTURE:** a separately
managed core service that continues while the UI application is fully quit. The
helper is app-owned.
