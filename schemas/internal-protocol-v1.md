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
| events_after | workspace_id, after | Up to 256 ascending events, sequence strictly greater than after |
| start_chain | workspace_id, target_id, chain (optional: `synthetic` default; `dns_recon`, `domain_recon`, `web_recon`, `web_analysis`, or `content_discovery`), options (optional object; `content_discovery` requires `{"wordlist_path": "..."}`) | Pending chain; execution occurs on worker |
| cancel_chain | workspace_id, chain_id | Cancellation requested |
| read_evidence | workspace_id, evidence_id | ID and hash-verified raw_json string |
| list_providers | none | Provider metadata plus live installation status (state/version) |

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
Web Recon, and Web Analysis can perform explicitly launched network activity.


### Provider Center status additions (v1 compatible)

`list_providers` remains global and takes no workspace parameter. Each flattened
provider entry may include optional `setup` (`install_command`, `homepage`,
`documentation`, all optional strings), owned by the provider definition.
`installation` with state `INSTALLED` may include optional `path`, resolved by the
core, alongside the existing `version`. Missing fields decode as absent. Built-in
providers use `BUILT_IN` and omit executable paths and installation commands.
Setup commands are static display/copy data, never executable IPC instructions.
The other installation states and protocol version remain unchanged.
