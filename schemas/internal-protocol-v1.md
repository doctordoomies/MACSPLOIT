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
{"protocol_version":1,"request_id":"example-1","result":{"core_version":"0.1.0","protocol_version":1,"offline_only":true}}
```

Failure replaces `result` with `error: {"code": "...", "message": "..."}`.
Swift checks version and request ID and decodes typed results. Error codes include
InvalidTarget, InvalidWorkspace, WorkspaceNotFound, ScopeViolation, DatabaseError,
MigrationFailure, ProviderFailure, ProviderMissing, ProviderTimeout,
ProviderUnsupported, EvidenceIntegrityError, BudgetExceeded, CoreBusy, InvalidState,
InvalidRequest, ProtocolMismatch, and transport CoreUnavailable. Invalid/oversized requests without a decodable ID return an
empty request ID; an oversized frame closes the helper session.

| Method | Parameters | Result |
| --- | --- | --- |
| hello | none | Version and offline-only status |
| list_workspaces | none | Workspace array |
| create_workspace | name, scope array | Persisted workspace |
| add_target | workspace_id, value | Classified stored target |
| snapshot | workspace_id | Consistent graph, runs, evidence metadata, recent events, cursor |
| events_after | workspace_id, after | Up to 256 ascending events, sequence strictly greater than after |
| start_chain | workspace_id, target_id, chain (optional: `synthetic` default, or `domain_recon`) | Pending chain; execution occurs on worker |
| cancel_chain | workspace_id, chain_id | Cancellation requested |
| read_evidence | workspace_id, evidence_id | ID and hash-verified raw_json string |
| list_providers | none | Provider metadata plus live installation status (state/version) |

IDs are UUID strings. Field names use snake_case; timestamps are RFC3339 UTC.
Maximum request: 64 KiB including newline. Maximum response: 8 MiB of JSON.
Swift waits at most 10 seconds for a response, closes a failed transport, and
can restart the helper on reconnect. Mutating commands are not automatically
retried. Clients reload snapshots after an ambiguous transport failure to inspect
committed state. Snapshot recent events are capped at 1,000; replay can retrieve
older events. SQLite migration versions are independent of protocol version.
