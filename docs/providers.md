# Providers

Status: **IMPLEMENTED** internal Rust provider contract, one offline provider, two
built-in native providers (DNS, HTTP analysis), and five real external providers:
Subfinder (passive), Nmap (active), HTTPX (active-low-impact), Katana
(active-low-impact), and ffuf (active content discovery).

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

Implemented capabilities: SUBDOMAIN_DISCOVERY, DNS_RESOLUTION, PORT_DISCOVERY,
SERVICE_FINGERPRINTING, HTTP_PROBING, WEB_CRAWLING. Risk classes: PASSIVE, ACTIVE_LOW_IMPACT, ACTIVE,
VALIDATION, LAB_ONLY. Passive and low-impact work runs on any in-scope target;
full ACTIVE work (Nmap) is authorized by the analyst explicitly launching the
chain and is still re-checked against per-asset scope before execution;
validation/lab are rejected.

The URL-based web providers (KatanaProvider, NativeHttpProvider, FfufProvider) accept an
explicitly scoped local/private URL target (`localhost`, loopback, `::1`, a private
IP/CIDR host, `.localhost`, or an `/etc/hosts` dev name) with custom ports and no
public-DNS prerequisite. Scope remains the authorization boundary — local/private status
grants nothing — and same-host handling is unchanged: hostname-based (port-agnostic) for
crawling/content discovery, and per-hop scope-checked for native-HTTP redirects, with
`localhost`/`127.0.0.1`/`::1` treated as distinct identities.

Provider statuses (metadata plus live installation state) are exposed to the UI
through the `list_providers` protocol method.

## Provider installation

MACSPLOIT can install a missing external provider on explicit user action; it never
installs anything silently and runs no shell. Installation is **typed**: a request names a
provider id and a method (`start_install`), and the Homebrew formula / official-installer
URL come only from a hardcoded reviewed matrix in `core/src/install` — a caller can never
supply a command or formula. Installs run asynchronously on a worker (they can take
minutes, longer than the client request timeout) and are observed via `install_status`;
installation output is status only and never enters workspace evidence.

| Provider | Homebrew formula | App-managed direct download | Official installer |
| --- | --- | --- | --- |
| Subfinder | `subfinder` | supported (staged) | GitHub releases |
| HTTPX | `httpx` | supported (staged) | GitHub releases |
| Katana | `katana` | supported (staged) | GitHub releases |
| ffuf | `ffuf` | supported (staged) | GitHub releases |
| Nmap | `nmap` | not appropriate (privileged .dmg) | nmap.org |

- **Install with Homebrew (implemented):** MACSPLOIT locates the `brew` executable
  (resolving a Homebrew symlink) and runs `brew install <reviewed formula>` as an
  executable + argument array through the process supervisor — never `/bin/sh -c`, never a
  command string, never `sudo`, and it never installs Homebrew itself. Exit status is
  captured; provider status is refreshed on completion; cancellation signals the process
  group.
- **Install without Homebrew (managed direct download):** the Go-based tools publish
  checksummed, per-architecture macOS archives on their official GitHub releases, so a
  verified app-managed install into `~/Library/Application Support/MACSPLOIT/Providers/`
  (HTTPS-only, official source, exact-arch match, bounded size, SHA-256 verification,
  traversal-safe extraction, atomic temp→destination, no system directories, no sudo) is
  the intended design. It is **typed and fail-closed in this build** — it routes the user
  to Homebrew or the official installer rather than shipping an unverified downloader —
  pending its dedicated security review. MACSPLOIT never does `curl | sh` or runs remote
  scripts. Nmap is excluded from app-managed download (its official standalone build is a
  privileged `.dmg`); install it with Homebrew or the official installer.
- **Use existing binary:** a compatible executable already on PATH or named by a provider
  override is first-class and never reinstalled.

MACSPLOIT needs a **compatible provider executable** — it does not depend on Homebrew.
Executable discovery resolves a candidate (including a Homebrew Cellar symlink) to a real,
executable regular file on PATH, `/opt/homebrew/bin`, `/usr/local/bin`, or an explicit
`MACSPLOIT_<TOOL>` override. Homebrew is presented in Provider Center and Recon only as an
optional recommended install method on macOS; an executable installed by any other method
and made available on PATH (or via an override) is fully supported. MACSPLOIT never
installs or updates providers and never runs a package manager.

## SyntheticDiscoveryProvider

The synthetic provider is version `1.0.0`, risk PASSIVE. It accepts
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

## NmapProvider

Status: **IMPLEMENTED** (Phase 1C; first ACTIVE provider). `nmap`, risk **ACTIVE**,
capabilities PORT_DISCOVERY and SERVICE_FINGERPRINTING, supported target type
IPAddress. It turns in-scope IPAddress assets (produced by DNS) into Port and
Service assets.

- **Active-provider rules.** Nmap runs only when the analyst explicitly launches
  Domain Recon and only against IPs that are in workspace scope. Scope is enforced
  by the orchestrator's per-asset in-scope filter immediately before execution, so
  an out-of-scope resolved IP (e.g. a shared third-party/cloud address) is never
  handed to Nmap even though its parent hostname is in scope. Scope is never
  widened. Launching the chain is the explicit approval for its active stage.
- **Scan profile.** Conservative and unprivileged: `-sT` (TCP connect, no root),
  `-sV` (service/version), `--top-ports 100`, `-oX -` (XML to stdout). No `-A`,
  `-O`, `-sS`, NSE (`-sC`/`--script`), timing/stealth presets, decoys, spoofing, or
  fragmentation. `-6` is added for an IPv6 batch. **No root is required.**
- **Why no NSE.** NSE scripts (even "default") broaden behavior and risk; Phase 1C
  is discovery/fingerprinting only. No CVE/vulnerability enrichment is performed.
- **Executable discovery / installation / version.** Same infrastructure as
  Subfinder (override → PATH → Homebrew/local → managed dir); MACSPLOIT never
  installs Nmap. `nmap --version` is parsed for the version, recorded on the run;
  a missing tool surfaces as MISSING and fails the stage with `ProviderMissing`.
- **Execution & evidence.** Runs through the centralized process supervisor
  (argument array, never a shell; bounded stdout/stderr; process-group
  cancellation). One provider run scans the whole in-scope IP batch (Nmap
  parallelizes internally); IPv4 and IPv6 are scanned in separate invocations
  (Nmap cannot mix families) and both raw XML documents are preserved in the
  evidence envelope before parsing.
- **Timeout / concurrency.** Nmap has a per-provider timeout of **120 s** (via
  `Provider::timeout`), independent of fast passive providers, inside an outer
  300 s chain-budget safety net. Concurrency is bounded to at most two processes
  (one per family).
- **XML parsing.** XML output only (never terminal text), parsed with `roxmltree`.
  Fields consumed: host address/status, port number/protocol/state, and service
  name/product/version/extrainfo/tunnel. Invalid XML fails the run with evidence
  preserved; unknown/other fields are ignored.
- **Assets & relationships.** Only reportable states (`open`, `open|filtered`)
  become assets; closed/filtered ports and down hosts are skipped (raw XML still
  has everything). A Port asset's canonical identity is `<ip>/<proto>/<portnum>`
  (so `443/tcp` on different hosts, and `53/tcp` vs `53/udp`, never collapse); a
  Service is `<ip>/<proto>/<portnum>/<name>`. Relationships: IP `exposes` Port,
  Port `serves` Service. Service fingerprints are stored as provider observations,
  not confirmed facts. Host down / no open ports is a successful (empty) run.

**Manual installation.** Install Nmap yourself (for example `brew install nmap`);
MACSPLOIT never installs it. Automated tests use `fixtures/fake-nmap.sh` (emitting
deterministic XML) injected via `MACSPLOIT_NMAP` — no real scanning.

## HTTPXProvider

Status: **IMPLEMENTED** (Phase 1D). HTTPX performs low-impact HTTP/HTTPS probing of
in-scope web services discovered by Nmap and produces Website and Technology assets.
It runs shell-free through the centralized supervisor with bounded output, timeout,
cancellation, JSONL parsing, evidence capture, and scope enforcement. Probe-URL hosts
are IP-aware: an IPv6 service literal is bracketed (`http://[2001:db8::10]:443`) so the
URL is valid, and the Website is linked back to its owning IP asset for both families.

Nmap and HTTPX also power **IP Recon** (Milestone 1.2): the same two providers run from a
single explicitly selected in-scope IP target (no DNS step), with the same conservative
Nmap profile and the same asset/evidence model. See [recon-chain](recon-chain.md).

## KatanaProvider

Status: **IMPLEMENTED** (Phase 2A). `katana`, risk **ACTIVE_LOW_IMPACT**,
capability WEB_CRAWLING, supported target type URL.

- Runs only from an explicitly selected in-scope HTTP(S) URL using a separate
  **Web Recon** chain, so Domain Recon does not require Katana.
- Standard non-headless mode only. MACSPLOIT does not enable automatic form filling,
  authentication flows, JavaScript crawling, or `-no-scope` in Phase 2A.
- Uses same-host `fqdn` scope, depth 2, a 20-second crawl duration, 5-second
  request timeout, 1 MiB response-read bound, bounded stdout/stderr, and provider
  cancellation.
- JSONL is treated as untrusted. Only valid same-host HTTP(S) endpoints are accepted;
  duplicates, malformed records, the root URL itself, and external hosts are dropped.
- Each discovered endpoint becomes a URL asset linked from the selected URL with a
  `has_endpoint` relationship. Raw Katana output is preserved as evidence before
  parsing.
- MACSPLOIT never installs Katana. Automated tests use `fixtures/fake-katana.sh`;
  the real network tool is never invoked by CI.

## NativeHttpProvider

Status: **IMPLEMENTED** (Phase 2B). `native_http`, risk **ACTIVE_LOW_IMPACT**,
capability WebAnalysis, supported target type URL, installation **BUILT_IN** (no
external tool). It takes an explicitly selected in-scope HTTP(S) URL and produces
normalized web-security metadata.

- **Built-in, Katana-independent.** It runs its own `Web Analysis` chain and shares
  no dependency on Katana; native analysis works even if Katana is not installed.
- **Transport boundary.** HTTP goes through an injectable `WebTransport`
  (`core/src/web`): the production `UreqTransport` makes one bounded request per hop
  with TLS validation left **on** (never disabled); the offline `StaticWebTransport`
  serves fixtures for tests and the `MACSPLOIT_WEB_FIXTURE` override.
- **What it normalizes.** Final response (status, content-type/length, server);
  security headers (HSTS, CSP, CSP-Report-Only, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy); **cookie security
  flags only** (name, Secure, HttpOnly, SameSite, Path — **never cookie values**);
  CORS headers; a **scope-checked redirect chain** (each hop validated against
  workspace scope, http(s)-only, no credentials; off-scope redirects are recorded
  but not followed); and conservative `robots.txt` parsing.
- **Bounds.** http/https only, no credential URLs, small redirect limit, request +
  operation deadline, capped body read (256 KiB), cooperative cancellation. No
  fuzzing, form submission, auth, or exploit payloads. Collection only — a missing
  header is not yet a Finding.
- **Model.** Enriches the `Website` asset for the URL via an `Observation`
  attributed to `native_http`; the full normalized report is stored as hashed
  evidence. No new asset types are created for headers/cookies.

## FfufProvider

Status: **IMPLEMENTED** (Phase 2C). `ffuf`, risk **ACTIVE**, capability
ContentDiscovery, supported target type URL. Bounded path/content discovery over an
explicitly selected in-scope HTTP(S) URL with a user-chosen wordlist.

- **Explicit only.** Runs solely from its own `Content Discovery` chain — never as
  part of Domain/Web/Web Analysis/DNS Recon. No hidden background fuzzing.
- **Wordlist.** The analyst explicitly selects a local wordlist; nothing is bundled
  or downloaded. The **Rust core** validates it (the Swift UI is not the boundary):
  UTF-8, ≤ 1 MiB, ≤ 500 usable entries, ≤ 512-byte lines; blank lines and `#`
  comments are ignored; binary/oversized/empty lists are rejected with a clear error
  (it never silently truncates). The wordlist path is carried as a typed `start_chain`
  option and re-validated by the provider.
- **Bounded, deterministic ffuf profile:** `-u <url>/FUZZ -w <list> -mc
  200,204,301,302,307,308,401,403,405 -t 10 -rate 10 -timeout 5 -json`. Redirects are
  **not** followed, **no recursion**, no extension/vhost/header/parameter fuzzing, no
  auth, no evasion. 404 creates no asset; raw output is still preserved.
- **Execution/evidence.** Shell-free process supervisor (argument array), bounded
  stdout/stderr, 90 s provider timeout, cancellation, version via `ffuf -V`. Raw JSON
  is hashed evidence before parsing. The persisted command **redacts the local
  wordlist path to its file name only** (keeping the URL target and provider identity).
- **Model.** Each accepted result becomes (or reuses) a `URL` asset with a
  `has_endpoint` relationship from the root URL; status/length/redirect live in
  observation/asset metadata and evidence. Same-host only — a discovery on another
  host is dropped (no cross-host scope expansion). Soft-404 detection is a documented
  initial limitation.

**Manual installation.** Install ffuf yourself (`brew install ffuf`); MACSPLOIT never
installs it. Automated tests use `fixtures/fake-ffuf.sh` + a small fixture wordlist.

## Next adapter boundary

Next Phase 2 work: historical URL intelligence (gau/waybackurls), then JavaScript
analysis. Content discovery remains an explicit active stage rather than something
silently folded into crawling.

**FUTURE:** approved installation/update tooling, dependency and
license metadata, version compatibility policy, and a public provider SDK. No
`provider.toml` contract or installer is frozen now. Never silently install a tool
or interpolate target input into a shell.


## Tool Manager / Provider Center (BETA)

Open **Tool Manager** in the sidebar to inspect every registered provider, even
without a selected workspace. The Rust core must be connected to load or refresh
status. The view renders `ProviderRegistry` / `list_providers` generically; new
providers appear once registered, without dedicated Swift cards. The ffuf provider
merged separately during this work already appears through the same view; future
providers such as user-scanner need no special rendering. This does not implement
new providers or change their roadmap.

Each card shows provider identity, description, capabilities, target types, risk,
offline/network behavior, built-in/external status, and installation diagnostics.
Built In, Installed, Missing, Unsupported, and Error remain distinct. Installed
external tools expose the core-resolved executable path and detected version;
unrecognized version output is explicitly **Version unknown**. Version probes
that fail or time out report Error. No minimum-version policy is introduced here;
Unsupported is supported by the schema/UI for providers that enforce one.

Refresh uses the existing bounded local version probes. It does not run a recon
chain or reconnect the core. Duplicate refreshes are disabled; a failed request
retains the previous list and displays an error. A previous result can become
stale until the next successful refresh. Availability is information, not target
authorization; scope enforcement still governs dispatch.

External providers own static setup commands and HTTPS help links. **MACSPLOIT
never silently installs providers.** Copy Install Command only writes the displayed
string to the clipboard. The user may choose to run it separately. There is no
installer, updater, package/dependency manager, or remote marketplace. Built-ins
need no installation and show no executable path. Executable discovery remains
entirely in Rust; Swift does not search PATH or fetch remote metadata.

### Compatible protocol v1 additions

`installation` may now include an optional `path` for `INSTALLED`. `ProviderStatus`
may include optional `setup` with `install_command`, `homepage`, and `documentation`.
Old v1 payloads without these fields still decode; existing consumers ignore new
fields. Setup is a defaultable provider trait method, so new providers can supply
help beside their definitions. Built-ins omit setup. The executable discovery
source (override/PATH/etc.) is not separately attributed in this version.
