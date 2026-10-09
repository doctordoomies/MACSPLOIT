# Internal core protocol v1

Status: **IMPLEMENTED**, private app/helper contract. Not a plugin or network API.
Rust types in `core/src/protocol.rs` and Swift Codable types in `MACSPLOITKit` are
the executable contract; cross-language integration tests verify compatibility.

Each stdin line contains one UTF-8 JSON request; stdout returns one response line.
The Swift transport serializes exchanges. Stderr is reserved for application logs.

```json
{"protocol_version":1,"request_id":"example-1","method":"hello","params":{}}
```

```json
{"protocol_version":1,"request_id":"example-1","result":{"core_version":"0.1.0","protocol_version":1,"offline_only":false}}
```

Failure replaces `result` with `error: {"code": "...", "message": "..."}`.
Swift checks version and request ID and decodes typed results. Error codes include
InvalidTarget, InvalidWorkspace, WorkspaceNotFound, ScopeViolation, DatabaseError,
MigrationFailure, ProviderFailure, ProviderMissing, ProviderTimeout,
ProviderUnsupported, WordlistMissing, WordlistTooLarge, EvidenceIntegrityError,
BudgetExceeded, CoreBusy, InvalidState, InvalidRequest, ProtocolMismatch, and
transport CoreUnavailable. Invalid/oversized requests without a decodable ID return an
empty request ID; an oversized frame closes the helper session.

| Method | Parameters | Result |
| --- | --- | --- |
| hello | none | Core/protocol version and legacy `offline_only` capability flag (false for the live-capable core) |
| list_workspaces | none | Workspace array |
| create_workspace | name, scope array | Persisted workspace |
| update_workspace_scope | workspace_id, scope array | Workspace with normalized replacement scope |
| add_target | workspace_id, value | Classified stored target |
| snapshot | workspace_id | Consistent graph, runs, evidence metadata, recent events, cursor |
| chain_results | workspace_id, chain_id | Read-only durable reconstruction of one Recon Chain: chain/target/stages/provider runs, scoped assets + Observations (including per-run metadata), relationship observations/provenance, and Evidence metadata. No raw Evidence body; no timestamp-only ownership inference. |
| events_after | workspace_id, after | Up to 256 ascending events, sequence strictly greater than after |
| start_chain | workspace_id, target_id, chain (optional: `synthetic` default; `dns_recon`, `domain_recon`, `ip_recon`, `web_recon`, `web_analysis`, `content_discovery`, `username_osint`, or `email_osint`), options (optional object; `content_discovery` requires `{"wordlist_path": "..."}`; OSINT chains accept `{"provider_id": "..."}`) | Pending chain; execution occurs on worker |
| cancel_chain | workspace_id, chain_id | Cancellation requested |
| read_evidence | workspace_id, evidence_id | ID and hash-verified raw_json string |
| list_providers | none | Provider metadata, live installation status (state/version), and `install` (reviewed method availability: `homebrew`, `managed_download`, `official_installer_url?`) |
| target_scope_status | workspace_id, target_id | `{authorized, required_scope_entry?}` computed with the core scope matcher; read-only, no network activity |
| authorize_target | workspace_id, target_id | Adds only the narrowest exact scope entry needed (no-op if already covered), persists it, re-checks authorization, and returns `{workspace, authorized, added_entry?}`; emits `WorkspaceScopeUpdated` (payload `added`, `source: "recon_authorization"`); no network activity |
| start_install | provider_id, method (`homebrew`, `managed_download`, `existing_binary`, `official_installer`) | Starts a typed, async provider install (worker thread); returns `{started, provider_id}`. Only the reviewed provider set is installable; execution is shell-free. Observe via `install_status` |
| cancel_install | none | Requests cancellation of a running install |
| install_status | none | `{running: {provider_id, method}?, last: InstallOutcome?}` where InstallOutcome is `{provider_id, method, status (SUCCEEDED/FAILED/CANCELLED/UNSUPPORTED), message, detail?}`; read-only |

`target_scope_status`, `authorize_target`, `start_install`, `cancel_install`, and
`install_status` are additive to protocol v1 (no version bump). Installation state is
in-memory and global (not workspace data), observed by polling `install_status`. Durable events gain a `ProviderCommand` type carrying a display-only, sanitized
command for the live console: the executable basename plus an argument array whose HTTP(S)
URLs have their query contents redacted (`https://host/path?<redacted>`) and userinfo
removed. It is never a shell string, is never executed, and carries no environment or
secrets; the exact execution argv and full output remain only in the hashed evidence.

IDs are UUID strings. Field names use snake_case; timestamps are RFC3339 UTC.
Maximum request: 64 KiB including newline. Maximum response: 8 MiB of JSON.
Swift waits at most 10 seconds for a response, closes a failed transport, and
can restart the helper on reconnect. Mutating commands are not automatically
retried. Clients reload snapshots after an ambiguous transport failure to inspect
committed state. Snapshot recent events are capped at 1,000; replay can retrieve
older events. SQLite migration versions are independent of protocol version. Workspace scope may
be replaced after creation; every supplied entry is normalized with the same
domain/wildcard/IP/CIDR rules used at creation, and provider dispatch continues to
enforce the stored scope independently of the SwiftUI state.

The `offline_only` hello field is retained in protocol v1 for wire compatibility.
It is now `false`: Synthetic Recon remains offline, while DNS Recon, Domain Recon,
IP Recon, Web Recon, Web Analysis, and Content Discovery can perform explicitly
launched network activity. Adding `ip_recon` is a backward-compatible extension of the
existing `chain` string enum and does not change the protocol version.


### Provider Center status additions (v1 compatible)

`list_providers` remains global and takes no workspace parameter. Each flattened
provider entry may include optional `setup` (`install_command`, `homepage`,
`documentation`, all optional strings), owned by the provider definition.
`installation` with state `INSTALLED` may include optional `path`, resolved by the
core, alongside the existing `version`. Missing fields decode as absent. Built-in
providers use `BUILT_IN` and omit executable paths and installation commands.
Setup commands are static display/copy data, never executable IPC instructions.
The other installation states and protocol version remain unchanged.


### OSINT additions (v1 compatible)

`start_chain` accepts `username_osint` (Username target) and `email_osint`
(EmailAddress target). `options.provider_id`, when present, must be a string naming a
registered provider that advertises the OSINT capability and the target's type;
otherwise the first compatible provider is used (`ProviderUnsupported` /
`InvalidRequest` / `InvalidTarget` on mismatch). Provider metadata gains the
`USERNAME_OSINT` and `EMAIL_OSINT` capability values; asset types gain `Username`,
`EmailAddress`, and `Account`; relationship types gain `has_account` and
`profile_url`. Snapshot observations gain an optional `metadata` object (absent/null
for legacy rows). Chains may finish `PARTIAL` (already a valid chain status) when a
provider reports incomplete results. `ProviderResults` event payloads may include
`partial` and a bounded `summary`; a failed parse emits `ProviderCompleted` with
`error_code`/`message`. Evidence envelopes may include `cancelled` and `artifacts`
(name, observed size, over-limit flag, and the evidence id/SHA-256 of a separately
stored structured report). Older clients ignore all new fields; no version bump.
