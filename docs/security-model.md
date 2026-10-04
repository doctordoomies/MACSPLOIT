# Security model

Status: **IMPLEMENTED** repository protections, offline foundation controls, and
passive external-tool, low-impact native DNS, and conservative active Nmap execution
controls (Phase 1A/1B/1C); higher-risk execution and distribution protections remain
planned.

## Repository

`doctordoomies/MACSPLOIT` stays PRIVATE. The ignore policy, staged audit, full-history
push audit, and exact private-destination check remain unchanged. See
[repository policy](repository-policy.md). Tests contain invented targets only.
No runtime database, evidence capture, credentials, environment file, Keychain
export, or build artifact belongs in Git. Local checks supplement review; they
cannot prove that arbitrary content contains no secret.

## Implemented boundaries

- Providers registered: the offline synthetic provider; Subfinder (passive external);
  native DNS (built-in, ACTIVE_LOW_IMPACT); Nmap (ACTIVE external); HTTPX (ACTIVE_LOW_IMPACT
  external); Katana (ACTIVE_LOW_IMPACT external); native HTTP analysis (built-in,
  ACTIVE_LOW_IMPACT); and ffuf content discovery (ACTIVE external). The application has
  no telemetry, tool installer, or privilege
  request. External tools run only when the analyst launches a chain and only if the
  tool is already installed. Native DNS uses the host's own system resolver config
  (never a hardcoded public resolver); there are no third-party DNS/passive-DNS API
  integrations (no SecurityTrails, Shodan, VirusTotal, etc.).
- Native HTTP analysis (ACTIVE_LOW_IMPACT, built-in) makes ordinary HTTP(S) requests
  to an explicitly selected in-scope URL only. It restricts schemes to http/https,
  rejects credential URLs, bounds redirects/body/time, follows redirects manually and
  **scope-checks every hop** (off-scope redirects are recorded but not followed), and
  leaves TLS validation enabled (never disabled). It records cookie security **flags
  only — never cookie values** — and does not fuzz, submit forms, authenticate, or
  send payloads.
- Content discovery (ffuf, ACTIVE) runs only from its own explicit chain, never
  automatically. The analyst selects a local wordlist; the **core** validates it
  (UTF-8, ≤ 1 MiB, ≤ 500 usable entries, ≤ 512-byte lines; binary/oversized/empty
  rejected, never silently truncated). The ffuf profile is bounded and deterministic
  (top status codes, ≤ 10 threads, ≤ 10 req/s, 5 s per request, **no redirect
  following, no recursion**, no extension/vhost/header/parameter fuzzing, no auth, no
  evasion). Discoveries are same-host only (no cross-host scope expansion). The
  persisted command **redacts the local wordlist path to its file name** so a private
  filesystem path is not stored in evidence.
- Local and private web targets (e.g. `http://localhost:3000`, `http://127.0.0.1:8080`,
  `http://[::1]:8080`, `http://192.168.1.50:8000`, `http://app.localhost:5173`, or an
  `/etc/hosts` dev name) are first-class for the web workflows, but **local/private status
  is never authorization**. The analyst must place the host in explicit workspace scope;
  the Rust core enforces it exactly as for public targets, and the SwiftUI layer is not the
  boundary. `localhost`, `127.0.0.1`, and `::1` are treated as **distinct authorization
  identities** (one does not imply another), and an exact `localhost` entry does not widen
  to `*.localhost` or to subdomain labels — a single-label wildcard suffix is rejected by
  scope normalization, so local wildcards must be authorized as explicit hosts. Same-host
  filtering for crawling (Katana) and content discovery (ffuf) is by **hostname and is
  port-agnostic** (another port on the same hostname is in-host; a different host identity
  is dropped), matching public behavior; cross-host redirects, crawl results, and ffuf
  results remain fail-closed and are only followed/recorded when the destination is itself
  in scope. Discovery never widens authorization, so link-local/cloud-metadata hosts such
  as `169.254.169.254` are never automatically added or probed from an authorized page. No
  `/etc/hosts` is parsed by MACSPLOIT; local names resolve through the normal system stack.
  TLS validation stays enabled for local HTTPS (a self-signed `https://localhost` surfaces a
  clear TLS failure rather than being silently trusted).
- Recon authorization flow (Milestone 1.3) keeps the Rust core as the authorization
  boundary while removing the leave-Recon-to-edit-scope friction. `target_scope_status`
  is read-only and reuses `scope::contains` (no second matcher in Swift, no network). An
  out-of-scope live Run requires an explicit **Authorize & Run** confirmation; on confirm,
  `authorize_target` adds **only the narrowest exact entry** (`scope::target_entry`: the
  domain/hostname/IP, or a URL's exact host — never a wildcard, CIDR, sibling host, or
  resolved IP), persists it, emits a durable `WorkspaceScopeUpdated` event tagged
  `source: "recon_authorization"`, and re-checks `scope::contains` before any provider
  starts (fail closed). Cancel mutates nothing and launches nothing. The scope event
  records operator intent and workspace configuration — it is not proof of permission.
- The live console shows a **display-only** sanitized command (`ProviderCommand` event:
  executable basename plus the argument array). It is never executed — process launch
  continues to use the exact executable path and argv — and carries no environment
  variables or secrets; the full command and raw output remain in the hashed evidence
  envelope. Future authenticated providers must redact sensitive arguments on this display
  path.
- Nmap is an ACTIVE provider. It uses a conservative, unprivileged profile
  (`-sT -sV --top-ports 100`, XML output) with **no NSE scripts, no OS detection, no
  SYN/stealth scan, no timing/evasion presets, no decoys/spoofing/fragmentation, and
  no root**. Scope is re-checked per IP immediately before scanning: a resolved IP
  that is out of workspace scope (e.g. shared third-party infrastructure) is filtered
  out and never scanned, even when its parent hostname is in scope. Launching the
  chain is the explicit approval for its active stage; scope is never widened. No CVE
  lookup, vulnerability scanning, credential testing, or exploitation is performed.
  An `ActiveProviderStarted` audit event records each active scan.
- Both the bundled helper and every external provider are launched by executable
  path and argument array — never through a shell. The child environment is minimal;
  targets are validated/normalized before use and can never become shell syntax.
- External tools run under a centralized process supervisor: bounded stdout/stderr,
  a wall-clock deadline within the chain budget, and cancellation that signals the
  whole child process group (no orphaned grandchildren). Untrusted tool output is
  size-, line-, and field-validated during parsing; one malformed line is skipped
  without failing the run. Each run records the exact command, arguments, and
  detected tool version, and stores raw stdout/stderr as hashed evidence.
- Rust validates targets and UUIDs, uses parameterized SQL, enforces workspace
  foreign keys, and writes graph/provenance/events in transactions.
- Each workspace uses a UUID-derived directory outside Git. Newly created private
  directories use mode 0700 and evidence files 0600. Files are protected by those
  directories, not encryption. Existing directory permissions are not repaired.
- Evidence IDs resolve only to their expected relative paths. Symlinks at checked
  workspace/evidence boundaries and integrity mismatches are rejected. This is
  not a hardened defense against a malicious process already running as the user.
- Scope checks use exact domains, wildcard label boundaries, and IP/CIDR parsing.
  Out-of-scope discoveries are not dispatched downstream. Passive and low-impact
  (DNS) work runs on any in-scope target; full Active work requires explicit
  authorization; validation/lab execution is disabled.
- One core owns a storage root at a time. Protocol frames, evidence, assets,
  targets, run count, and concurrency are bounded. Startup recovers interrupted
  work as FAILED without rescheduling.

## Logs, evidence, and audit

`logs/application.jsonl` contains helper lifecycle and operation status, excluding
target values and evidence bodies. Successful event polls are omitted. Logs rotate
on helper startup above 1 MiB, retaining one previous file; they do not yet have
continuous rotation. Provider runs and raw output live in workspace storage.
SQLite `audit_events` records WorkspaceCreated, TargetAdded, ReconStarted,
ActiveProviderStarted, and ReconCancelled separately from UI activity events.

Structured errors cross the bridge; storage error messages do not expose raw SQL,
local paths, or captured content. The evidence viewer shows the stored provider
envelope (including bounded raw stdout/stderr) after Rust verifies its SHA-256.
Subfinder output is passive subdomain data; general secret redaction and hardened
rendering of arbitrary scanner output remain prerequisites for higher-risk tools.

## Planned and future controls

**IMPLEMENTED for passive external execution (Phase 1A):** subprocess supervision
with argument arrays, bounded output, a run deadline, and process-group
cancellation; parser-output validation; exact command/argument/version recording.

**PLANNED before higher-risk execution:** a dedicated per-provider timeout,
per-host/request limits, scope rechecks on resolved addresses and HTTP redirects,
and UI approval for tool installation and any active execution. Expand authorization
and audit controls as those actions are added.

**FUTURE:** Keychain-backed API credentials, retention/deletion/export controls,
redacted display versus protected originals, signed/notarized distribution and
App Sandbox decisions, peer authorization for a persistent service. The development
app is ad-hoc signed and unsandboxed, runs as the current user, and requires no
root access. There is no release or App Store distribution in this phase.

Normal reconnaissance must not automatically attempt authentication, execute
payloads, obtain credentials, persist remotely, or escalate findings into
compromise. Validation/lab functionality stays separate and opt-in. Wireless
attacks and hardware execution remain outside the initial platform.
