# Security model

Status: **IMPLEMENTED** repository protections and offline foundation controls;
external-tool and distribution protections remain planned.

## Repository

`doctordoomies/MACSPLOIT` stays PRIVATE. The ignore policy, staged audit, full-history
push audit, and exact private-destination check remain unchanged. See
[repository policy](repository-policy.md). Tests contain invented targets only.
No runtime database, evidence capture, credentials, environment file, Keychain
export, or build artifact belongs in Git. Local checks supplement review; they
cannot prove that arbitrary content contains no secret.

## Implemented boundaries

- The only provider is synthetic; the application has no scanner, DNS lookup,
  socket, external HTTP request, telemetry, tool installer, or privilege request.
- Foundation Process launches the bundled helper by path and argument array.
  The environment is minimal; targets are structured JSON, never shell commands.
- Rust validates targets and UUIDs, uses parameterized SQL, enforces workspace
  foreign keys, and writes graph/provenance/events in transactions.
- Each workspace uses a UUID-derived directory outside Git. Newly created private
  directories use mode 0700 and evidence files 0600. Files are protected by those
  directories, not encryption. Existing directory permissions are not repaired.
- Evidence IDs resolve only to their expected relative paths. Symlinks at checked
  workspace/evidence boundaries and integrity mismatches are rejected. This is
  not a hardened defense against a malicious process already running as the user.
- Scope checks use exact domains, wildcard label boundaries, and IP/CIDR parsing.
  Out-of-scope discoveries are not dispatched downstream. Active risk classes
  require explicit authorization; validation/lab execution is disabled.
- One core owns a storage root at a time. Protocol frames, evidence, assets,
  targets, run count, and concurrency are bounded. Startup recovers interrupted
  work as FAILED without rescheduling.

## Logs, evidence, and audit

`logs/application.jsonl` contains helper lifecycle and operation status, excluding
target values and evidence bodies. Successful event polls are omitted. Logs rotate
on helper startup above 1 MiB, retaining one previous file; they do not yet have
continuous rotation. Provider runs and raw output live in workspace storage.
SQLite `audit_events` records WorkspaceCreated, TargetAdded, ReconStarted, and
ReconCancelled separately from UI activity events.

Structured errors cross the bridge; storage error messages do not expose raw SQL,
local paths, or captured content. The evidence viewer intentionally shows complete
synthetic JSON after Rust verifies its SHA-256. General secret redaction and safe
rendering of arbitrary scanner output are prerequisites for real providers.

## Planned and future controls

**PLANNED before real execution:** supervise subprocesses with argument arrays,
output/runtime limits and process-group cancellation; validate parser output;
recheck scope on addresses/redirects; record exact versions/arguments; show tool
installation and active execution for explicit approval. Expand authorization
and audit controls when those actions actually exist.

**FUTURE:** Keychain-backed API credentials, retention/deletion/export controls,
redacted display versus protected originals, signed/notarized distribution and
App Sandbox decisions, peer authorization for a persistent service. The development
app is ad-hoc signed and unsandboxed, runs as the current user, and requires no
root access. There is no release or App Store distribution in this phase.

Normal reconnaissance must not automatically attempt authentication, execute
payloads, obtain credentials, persist remotely, or escalate findings into
compromise. Validation/lab functionality stays separate and opt-in. Wireless
attacks and hardware execution remain outside the initial platform.
