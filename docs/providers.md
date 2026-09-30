# Providers

Status: **IMPLEMENTED** internal Rust provider contract, one offline provider, one
real external provider (Subfinder), and one built-in native provider (DNS).

The `Provider` trait separates `metadata`, `installation`, `execute`, and `parse`.
Metadata exposes ID, name, description, version, capabilities, supported target
types, risk, and an `offline` flag. `installation` reports whether a real tool is
present (INSTALLED/MISSING/UNSUPPORTED_VERSION/EXECUTION_ERROR) or that a provider
is native (BUILT_IN). `execute` returns a structured
`Execution` (command, stdout, stderr, exit status, pid, timings) captured by the
centralized process supervisor; `parse` consumes that `Execution`. A registry
selects by capability and supported target type, or by a stage-pinned provider id
when a capability is offered by more than one provider. SwiftUI never selects
executables or parses raw provider output. This is an internal interface, not a
third-party plugin ABI.

Implemented capabilities: SUBDOMAIN_DISCOVERY, DNS_RESOLUTION,
SERVICE_FINGERPRINTING. Risk classes: PASSIVE, ACTIVE_LOW_IMPACT, ACTIVE,
VALIDATION, LAB_ONLY. Active classes require explicit authorization and scope;
validation/lab are rejected. Both registered providers are PASSIVE; no active
provider is registered.

Provider statuses (metadata plus live installation state) are exposed to the UI
through the `list_providers` protocol method.

## SyntheticDiscoveryProvider

The only implementation is `synthetic`, version `1.0.0`, risk PASSIVE. It accepts
`example.test` and produces invented JSON without DNS, sockets, external requests,
subprocesses, or installed tools. Resolution and service stages consume scoped
assets discovered earlier in the current chain. All addresses are documentation
addresses in `192.0.2.0/24`.

The adapter deliberately reports duplicate/case-variant subdomains to exercise
normalization while retaining observations. Its parser validates the synthetic
output envelope, size, and discovery count. The core validates asset identities
and relationship sources transactionally before persistence. Tests cover metadata,
structured parsing, malformed input, graph shape, deduplication, and evidence.

Each capability execution persists a provider-run record with identity/version,
input, start/end, status, evidence reference, and exit status. Raw JSON is hashed
and recorded before parsing. The synthetic success exit status is 0; no real
process is implied. Provider records/evidence are separate from ordinary helper
logs and user-action audit records.

## SubfinderProvider

Status: **IMPLEMENTED** (Phase 1A). `subfinder`, risk PASSIVE, capability
SUBDOMAIN_DISCOVERY, supported target type Domain, `offline=false`. It is the first
provider backed by a real external tool: ProjectDiscovery's `subfinder`.

- **Executable discovery.** The provider never hardcodes a path. `ToolConfig`
  locates `subfinder` via an explicit override (`MACSPLOIT_SUBFINDER`), then `PATH`,
  then `/opt/homebrew/bin` and `/usr/local/bin`, then a managed tools directory
  (`MACSPLOIT_TOOLS_DIR`). Only regular, owner-executable, non-symlink files
  qualify, so Apple Silicon and Intel installs both work.
- **Installation status.** Reported as INSTALLED (with a detected version), MISSING,
  UNSUPPORTED_VERSION, or EXECUTION_ERROR. MACSPLOIT never installs Subfinder; a
  missing tool is surfaced to the UI and fails a run with `ProviderMissing`.
- **Version detection.** `subfinder -version` output is scanned for a semantic
  version. If none is found the version is recorded as `unknown` rather than a
  fabricated value. The detected version is stored on every provider run.
- **Execution.** Runs through the centralized process supervisor with an argument
  array (`-d <domain> -silent -oJ`) — never a shell — with bounded stdout/stderr,
  a wall-clock deadline within the chain budget, and cooperative cancellation. The
  target is validated and normalized by the classifier before use, so it cannot be
  a shell fragment or an option.
- **Structured output.** Subfinder JSON-lines (`-oJ`) are consumed; each line's
  `host` is normalized and validated. Malformed lines are skipped without failing
  the run; duplicates and case/trailing-dot variants collapse to one asset while
  observations are preserved. Genuine children of the target gain a `has_subdomain`
  relationship; unrelated hosts are preserved for evidence without a false parent.
- **Evidence.** Every run stores a JSON envelope with the command, provider version,
  exit status, timings, and the raw stdout/stderr, hashed before parsing so neither
  a tool failure nor a parser failure can destroy the record. Runtime evidence
  stays outside Git.

Subfinder is not resolved to IPs, port-scanned, or HTTP-probed in Phase 1A — it only
turns a Domain into Subdomains. See [recon-chain](recon-chain.md).

**Manual installation.** Install Subfinder yourself (for example
`brew install subfinder`, or a release binary on `PATH`). MACSPLOIT will not install
it. Automated tests never invoke the real tool — they use an offline fake executable
(`fixtures/fake-subfinder.sh`) injected through `MACSPLOIT_SUBFINDER`.

## NativeDnsProvider

Status: **IMPLEMENTED** (Phase 1B). `native_dns`, risk **ACTIVE_LOW_IMPACT**,
capability DNS_RESOLUTION, supported target types Domain and Hostname,
installation **BUILT_IN** (no external tool). It resolves the Subdomain/Hostname/
Domain assets discovered earlier in the chain into IPAddress assets.

- **Native first.** DNS is implemented in Rust with `hickory-resolver` rather than
  an external CLI, so ordinary resolution works out of the box: no install step,
  simpler offline tests, lower overhead, normalized results, and a base capability
  even if a `DnsxProvider` is added later. See [architecture](architecture.md).
- **Resolver boundary.** Resolution sits behind an injectable `DnsResolver` trait.
  Production uses the **system resolver configuration** (never a hardcoded public
  resolver such as 8.8.8.8; if the system config cannot be read it fails closed).
  All automated tests use an offline `StaticDnsResolver` — no network.
- **Records.** A (IPv4) and AAAA (IPv6). MX/NS/TXT/CNAME/etc. are out of scope for
  Phase 1B. CNAMEs are not modeled as assets yet (deferred; may be preserved in
  evidence later).
- **Outcomes.** Classified per host: RESOLVED, NO_RECORDS, NXDOMAIN, TIMEOUT,
  TEMPORARY_FAILURE, INVALID_NAME, RESOLVER_FAILURE, CANCELLED. A missing record
  type is not an app failure — partial success (A succeeds, AAAA fails) keeps the
  A result. The batch completes even if some hosts fail.
- **Execution model.** One provider run resolves the whole batch of hostnames
  (not one run per host), with bounded per-query timeouts and bounded concurrency
  (default 16), a deadline within the chain budget, and cooperative cancellation.
  It records the same provider run / evidence / events / provenance as any provider;
  the provider version is recorded as the core version.
- **Assets & relationships.** Each address becomes (or reuses) an IPAddress asset;
  a `resolves_to` relationship links host → IP. Many-to-many is supported (a host
  with several IPs; several hosts sharing an IP). Duplicate addresses de-duplicate
  to one asset while observations preserve provenance and observation time.
- **Scope.** ACTIVE_LOW_IMPACT resolves in-scope assets without a separate approval
  gate; out-of-scope hosts are not resolved and out-of-scope IPs are marked
  `in_scope=false` and excluded from downstream dispatch.
- **Freshness.** Phase 1B has no DNS freshness/caching model: a resolved asset is
  a point-in-time observation, not a guarantee of current correctness. Documented
  as a limitation; a freshness/caching layer is future work.

Future providers (`DnsxProvider`, `MassDnsProvider`) could supply the same
DNS_RESOLUTION capability under this boundary; none are implemented now.

## Next adapter boundary

**PLANNED — Nmap** (ports/services on resolved IP addresses) is the next step
(Phase 1C), followed by **HTTPX** (HTTP probing), each introduced independently and
only after its timeout, cancellation, output-bound, and scope tests pass.

**FUTURE:** approved installation/update tooling (Tool Manager), dependency and
license metadata, version compatibility policy, and a public provider SDK. No
`provider.toml` contract or installer is frozen now. Never silently install a tool
or interpolate target input into a shell.
