# Assets and persistence

Status: **IMPLEMENTED** initial domain, graph, provenance, and migration 001.

## Identity and normalization

Workspace, target, asset, relationship, run, task, event, and evidence IDs are
opaque UUIDs. Assets are unique by `(workspace_id, asset_type, canonical_identity)`.
They store a display value, JSON metadata, and first/last seen times. Repeat
observations update last-seen without changing identity or deleting provenance.

Implemented asset types: Domain, Subdomain, Hostname, IPAddress, Port, Service,
Website, URL, Endpoint, Technology, Certificate. Synthetic recon populates Domain, Subdomain, IPAddress, Port, and Service.
Target classification recognizes domains, HTTP(S) URLs, IPv4/IPv6, CIDRs,
hostnames, @usernames, and email addresses. PhoneNumber, Repository, and Unknown
are reserved enum values. CIDR and identity targets currently have no asset nodes
or providers; domain, hostname, IP, and URL input creates an initial analyst asset.

The URL library supplies URL/IDNA normalization; std IP types and ipnet normalize
addresses and network prefixes. Domain case and one trailing dot are normalized.
URLs retain path/query and drop fragments; embedded credentials are rejected.
Username/email local-part case is retained. No public-suffix inference occurs.
Port and service identities include address, transport, and port so different
hosts do not collapse into a single node. Future external adapters need stronger
typed port/service validation before accepting untrusted output of those types.

## Relationships and provenance

Relations: `has_subdomain`, `resolves_to`, `exposes`, `serves`, `has_endpoint`, and
`uses_technology`. Each relation is unique by workspace, endpoints, and type.
Assets and edges retain separate observations linked to provider run, evidence,
source asset, timestamp, and confidence. Original observed values survive
canonicalization: three reports of `api.example.test` (including uppercase)
produce one asset and three observations per run.

Raw evidence lives outside SQLite in UUID-named JSON files. The database stores
its media type, byte count, SHA-256, provider/run, target, timestamp, and relative
path. Evidence reads check containment and hash integrity. The asset inspector
shows incoming/outgoing relationships, observation source/value/time,
and links to evidence. Relationship observations remain available in storage;
a dedicated edge inspector is future work.

## Migration 001

| Tables | Responsibility |
| --- | --- |
| workspaces, scope_entries | Workspace identity and explicit scope |
| targets | Original/normalized inputs and optional initial asset |
| assets, asset_relationships | Canonical nodes and edges |
| observations, relationship_observations | Per-run provenance without deduplication loss |
| provider_runs | Provider/version, input, timing, status, output, exit status |
| tasks, chain_runs, chain_stages | Durable execution and stage state |
| evidence | Protected raw-file metadata and integrity hashes |
| events | Ordered replayable domain changes |
| audit_events | Workspace creation, target addition, recon start/cancel |

Migration handling detects `user_version`, applies version 1 transactionally,
reopens existing stores, and rejects newer schemas. Foreign keys, workspace
composite keys, enum checks, JSON validity checks, and uniqueness constraints
backstop application validation. Discovery writes roll back as a unit on an
invalid relationship or provenance reference.

**PLANNED:** DNSRecord/CIDR graph nodes as real adapters require them, provider
catalog persistence, typed attribute evolution, and normalization versioning.
**FUTURE:** findings, notes, reports, exports, identity/repository/hardware models.
The planned finding dimensions remain severity (INFO through CRITICAL), confidence
(LOW through CONFIRMED), and review status (NEW, REVIEWING, CONFIRMED,
FALSE_POSITIVE, RESOLVED, ACCEPTED_RISK); none is implemented as findings yet.
