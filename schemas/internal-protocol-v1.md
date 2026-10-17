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
| start_chain | workspace_id, target_id, chain (optional: `synthetic` default; `dns_recon`, `domain_recon`, `ip_recon`, `web_recon`, `web_analysis`, `content_discovery`, `username_osint`, `email_osint`, `phone_osint`, or `domain_osint`), options (optional object; `content_discovery` requires `{"wordlist_path": "..."}`; OSINT chains accept `{"provider_id": "..."}`) | Pending chain; execution occurs on worker |
| cancel_chain | workspace_id, chain_id | Cancellation requested |
| read_evidence | workspace_id, evidence_id | ID and hash-verified raw_json string |
| list_providers | none | Provider metadata, live installation status (state/version), and `install` (reviewed method availability: `homebrew`, `managed_download`, `managed_python`, `managed` (any app-managed method = "Install with MACSPLOIT"), `official_installer_url?`) |
| target_scope_status | workspace_id, target_id | `{authorized, required_scope_entry?}` computed with the core scope matcher; read-only, no network activity |
| authorize_target | workspace_id, target_id | Adds only the narrowest exact scope entry needed (no-op if already covered), persists it, re-checks authorization, and returns `{workspace, authorized, added_entry?}`; emits `WorkspaceScopeUpdated` (payload `added`, `source: "recon_authorization"`); no network activity |
| start_install | provider_id, method (`managed` = "Install with MACSPLOIT"; `homebrew`; `managed_download`; `managed_python`; `existing_binary`; `official_installer`) | Starts a typed, async provider install (worker thread); returns `{started, provider_id}`. `managed` is resolved by the core to the concrete reviewed method (binary download or the pinned-`uv` managed-Python path). Only the reviewed provider set is installable; execution is shell-free. Observe via `install_status` |
| cancel_install | none | Requests cancellation of a running install |
| install_status | none | `{running: {provider_id, method}?, last: InstallOutcome?, events: [InstallEvent]}` where InstallOutcome is `{provider_id, method, status (SUCCEEDED/FAILED/CANCELLED/UNSUPPORTED), message, detail?}` and InstallEvent is `{seq, timestamp, kind (STAGE/COMMAND/STDOUT/STDERR/INFO), text}`; the bounded event log drives the read-only Install Console (reset per install). Read-only |
| propose_correlation | workspace_id, left_asset_id, right_asset_id, basis (`analyst_review`, `shared_public_record`, `shared_identifier`), confidence (`LOW`, `MEDIUM`, `HIGH`), rationale (1–1,024 bytes), observation_ids (1–20) | A `PROPOSED` Correlation. Refused (`InvalidRequest`) unless both assets are cited by evidence-backed observations; `shared_identifier` is capped at `LOW`; a second proposal for the same pair is `CorrelationExists`. Never modifies assets |
| review_correlation | workspace_id, correlation_id, decision (`confirm`, `reject`, `retract`, `reopen`), note (1–1,024 bytes) | The updated Correlation; only `PROPOSED→CONFIRMED/REJECTED`, `CONFIRMED→RETRACTED`, `REJECTED/RETRACTED→PROPOSED`; otherwise `InvalidTransition` |
| create_finding | workspace_id, finding (`NewFinding`) | Durable Finding with Asset/Evidence links and history; validates bounds, enum values and same-workspace references |
| update_finding | workspace_id, finding_id, edit (`FindingEdit`) | Atomically updates analyst fields; status and source provenance remain separate |
| set_finding_status | workspace_id, finding_id, status, note | Validated lifecycle transition with durable review note; invalid/self transition → `InvalidTransition` |
| link_finding_evidence | workspace_id, finding_id, evidence_id | Idempotent same-workspace Evidence link; returns updated Finding |
| unlink_finding_evidence | workspace_id, finding_id, evidence_id | Removes only the link; retained Evidence is untouched; returns updated Finding |
| result_projection | workspace_id, chain_id | Bounded read-only normalized projection from durable observations and same-run relationship provenance; no provider execution or raw output |

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

M6 completion adds `phone_osint` (PhoneNumber target, E.164) and `domain_osint` (Domain
target that must be in workspace scope; `PASSIVE` providers only — otherwise
`ScopeViolation`), capability values `PHONE_OSINT` and `DOMAIN_OSINT`, asset type
`PhoneNumber`, and relationship types `has_email`, `has_nameserver`, and `observed_ip`.
Every OSINT run summary's `subject_kind` is SCREAMING_SNAKE_CASE and consistent across
workflows: `USERNAME`, `EMAIL`, `PHONE`, `DOMAIN` (Domain was normalized from the former
lowercase `"domain"`). Clients interpret it case-insensitively. Domain OSINT run
summaries use `subject_kind: "DOMAIN"` with host/email/IP/nameserver counts (RDAP adds a
minimized `registration` object); their per-asset observations use `kind:
"osint_domain_observation"` with `passive`, `historical`, `liveness: "unverified"`, and
bounded `facts`. Phone run summaries use `subject_kind: "PHONE"` with per-source
`sources` facts and `errors`.

### Correlation additions (v1 compatible, Issue #67)

`snapshot` gains `correlations`: `[{id, workspace_id, left_asset_id, right_asset_id,
basis, confidence, status (PROPOSED/CONFIRMED/REJECTED/RETRACTED), rationale,
observation_ids, evidence_ids, created_by, created_at, updated_at, reviews: [{id,
from_status?, to_status, note, actor, timestamp}]}]` (absent from older cores; clients
treat a missing key as empty). Durable events gain `CorrelationProposed` and
`CorrelationReviewed`. Correlations are created only by `propose_correlation`; no chain
or provider creates one. See `docs/osint-correlation.md`.

### Findings and shared projection additions (v1 compatible, Issue #76)

`snapshot` gains `findings`, with each Finding carrying `id`, `workspace_id`, `title`,
`severity`, `confidence`, `status`, `description`, `reproduction`, `remediation`,
`source_provider?`, `source_run_id?`, `tags`, `cwe_ids`, `cve_ids`, `affected_assets`
(`[{asset_id, is_primary}]`), `evidence_ids`, `created_by`, `created_at`, `updated_at`,
and oldest-first `history` (`[{id, kind, from_value?, to_value?, note, actor, timestamp}]`).
Swift treats absent `findings` in older snapshots as empty. Older clients ignore the
new key. No protocol version bump or existing result-renderer replacement is required.

`NewFinding` requires `title`, `severity`, `confidence`; optional `status` defaults
OPEN, optional text/lists default empty. It accepts `primary_asset_id?`,
`additional_asset_ids`, `evidence_ids`, `source_provider?`, `source_run_id?`.
`FindingEdit` accepts only optional `title`, `severity`, `confidence`, `description`,
`reproduction`, `remediation`, `tags`, `cwe_ids`, `cve_ids`; absent/null leaves a field
unchanged, empty strings/arrays explicitly clear optional content. Status uses its own
command and note; attribution is immutable. Finding commands return the complete
updated Finding. Unknown/wrong-workspace finding IDs yield `FindingNotFound`;
invalid links/fields yield `InvalidRequest` (`AssetNotFound` for affected assets),
collection capacity yields `BudgetExceeded`, and invalid lifecycle moves yield
`InvalidTransition`. Malformed enums fail request decoding. No mutation is auto-retried.

`result_projection` returns `{workspace_id, chain_id, chain_name, items}`. A ResultItem
has `kind` (`ASSET_OBSERVATION`/`RELATIONSHIP_OBSERVATION`), `observation_id`, `asset_id`,
`asset_type`, `asset_identity`, optional `source_asset_id`, `run_id`, `provider_id`,
`discovered_by`, optional `evidence_id`, `observed_value`, `confidence`, `timestamp`,
`metadata`, `metadata_omitted`. Provider confidence is not analyst Finding confidence.
Only observations attributable through provider runs for the requested chain enter
this read model. Relationship kind additionally requires existing relationship-observation
provenance for the same provider run/Evidence and endpoint pair. Canonical reuse never
removes run provenance. Missing chains (including wrong workspace) yield `InvalidRequest`;
SQL errors propagate as `DatabaseError`; unsupported old/new schema yields
`MigrationFailure` with no migration/write performed by the query.

Projection limits: 10,000 items, 6 MiB total JSON; overflow → `ResultsTooLarge`.
Metadata over 32 KiB becomes null with `metadata_omitted: true`; historical absence
stays null with false. Metadata remains untrusted normalized data. Raw output stays in
Evidence. Durable events gain `FindingCreated`, `FindingUpdated`, `FindingStatusChanged`,
with IDs/small status summaries only. Migration 008 is independent of protocol v1.
See [Findings](../docs/findings.md) for enum values, transitions, field bounds and
owner acceptance; TLS/Nuclei/CVE enrichment/reporting/AI remain deferred.
