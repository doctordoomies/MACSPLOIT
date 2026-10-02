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
  external); Katana (ACTIVE_LOW_IMPACT external); and native HTTP analysis (built-in,
  ACTIVE_LOW_IMPACT). The application has no telemetry, tool installer, or privilege
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
- Nmap is the only ACTIVE provider. It uses a conservative, unprivileged profile
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
