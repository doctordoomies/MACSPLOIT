# Asset and persistence design

Status: design only; executable schemas and migrations follow in Phase 0.

Assets are the central model. Scanner runs provide observations about them.
An asset has an opaque ID, workspace ID, type, canonical identity, display value,
typed attributes, first/last observation times, and provenance references.
Uniqueness is scoped to `(workspace, type, canonical identity)`; normalization
must not collapse distinct endpoints or erase useful evidence.

Initial types: Domain, Subdomain, Hostname, DNSRecord, IPAddress, CIDR, Port,
Service, Website, URL, Endpoint, Technology, and Certificate. Findings and evidence
have their own records and graph references. Person/identity, repository/source,
wireless, Bluetooth, SDR, and hardware types are later extensions.

Relationships have an ID, workspace ID, source and destination asset IDs, typed
relation, and provenance. Initial relations include `has_subdomain`, `resolves_to`,
`exposes`, `serves`, `has_endpoint`, and `uses_technology`. Each observation links
to its source asset, provider run, timestamp, confidence, and evidence where
available. Multiple sources support one normalized relationship without losing
their individual observations.

Normalize IPv4 and IPv6 using address libraries; retain network prefix lengths.
Use maintained URL, IDNA, Public Suffix List, and phone-parsing implementations
when those target classes are introduced. Never infer registrable domains by
splitting the final two labels. Version normalization decisions when identity
semantics change.

## Proposed relational boundaries

| Entity | Responsibility |
| --- | --- |
| workspaces / scope_entries | Independent assessment identity and allowed boundaries |
| targets | Analyst inputs, classified type, and normalized asset link |
| assets / asset_relationships | Canonical graph nodes and edges |
| observations | Provenance linking entities to runs and evidence |
| providers / provider_runs | Provider identity/version and reproducible execution metadata |
| tasks / chain_runs / chain_stages | Durable execution state and dependencies |
| findings | Title, description, severity, confidence, asset, status, references, remediation |
| evidence / finding_evidence | Raw artifacts, integrity hashes, timestamps, associations |
| notes / reports | Analyst context and export metadata |
| audit_events | Ordered history of state changes and user approvals |

Use foreign keys and workspace isolation checks. Evidence files are referenced
by contained workspace paths; do not accept arbitrary absolute paths from tools.
Evidence provenance must survive asset deduplication.

Severity is INFO, LOW, MEDIUM, HIGH, or CRITICAL. Confidence is LOW, MEDIUM, HIGH,
or CONFIRMED. Finding status is NEW, REVIEWING, CONFIRMED, FALSE_POSITIVE, RESOLVED,
or ACCEPTED_RISK. These are separate dimensions. Correlate duplicate findings
without dropping provider observations or analyst notes.

Version JSON exports independently of database migrations. The planned export
contains workspace, targets, assets, relationships, findings, and evidence
references. Exporting private content requires an explicit user action.
