CREATE TABLE workspaces (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE scope_entries (
    workspace_id TEXT NOT NULL REFERENCES workspaces(id), value TEXT NOT NULL,
    PRIMARY KEY (workspace_id, value)
);
CREATE TABLE assets (
    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    asset_type TEXT NOT NULL, canonical_identity TEXT NOT NULL, display_value TEXT NOT NULL,
    metadata TEXT NOT NULL CHECK(json_valid(metadata)), first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    UNIQUE(workspace_id, id), UNIQUE(workspace_id, asset_type, canonical_identity)
);
CREATE TABLE targets (
    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    original_value TEXT NOT NULL, normalized_value TEXT NOT NULL, target_type TEXT NOT NULL,
    created_at TEXT NOT NULL, asset_id TEXT,
    UNIQUE(workspace_id, id), UNIQUE(workspace_id, target_type, normalized_value),
    FOREIGN KEY(workspace_id, asset_id) REFERENCES assets(workspace_id, id)
);
CREATE TABLE asset_relationships (
    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    source_asset_id TEXT NOT NULL, destination_asset_id TEXT NOT NULL,
    relationship_type TEXT NOT NULL CHECK(relationship_type IN
      ('has_subdomain','resolves_to','exposes','serves','has_endpoint','uses_technology')),
    created_at TEXT NOT NULL, UNIQUE(workspace_id, id),
    UNIQUE(workspace_id, source_asset_id, destination_asset_id, relationship_type),
    FOREIGN KEY(workspace_id, source_asset_id) REFERENCES assets(workspace_id, id),
    FOREIGN KEY(workspace_id, destination_asset_id) REFERENCES assets(workspace_id, id)
);
CREATE TABLE chain_runs (
    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id), target_id TEXT NOT NULL,
    name TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('PENDING','RUNNING','COMPLETED','PARTIAL','FAILED','CANCELLED')),
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, error_code TEXT,
    UNIQUE(workspace_id, id), FOREIGN KEY(workspace_id, target_id) REFERENCES targets(workspace_id, id)
);
CREATE TABLE chain_stages (
    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id), chain_id TEXT NOT NULL,
    position INTEGER NOT NULL, name TEXT NOT NULL, capability TEXT,
    status TEXT NOT NULL CHECK(status IN ('QUEUED','RUNNING','PAUSED','COMPLETED','FAILED','CANCELLED')),
    started_at TEXT, ended_at TEXT, UNIQUE(workspace_id, id), UNIQUE(chain_id, position),
    FOREIGN KEY(workspace_id, chain_id) REFERENCES chain_runs(workspace_id, id)
);
CREATE TABLE tasks (
    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id), chain_id TEXT NOT NULL,
    stage_id TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('QUEUED','RUNNING','PAUSED','COMPLETED','FAILED','CANCELLED')),
    updated_at TEXT NOT NULL, UNIQUE(workspace_id, id), UNIQUE(stage_id),
    FOREIGN KEY(workspace_id, chain_id) REFERENCES chain_runs(workspace_id, id),
    FOREIGN KEY(workspace_id, stage_id) REFERENCES chain_stages(workspace_id, id)
);
CREATE TABLE provider_runs (
    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id), chain_id TEXT NOT NULL,
    stage_id TEXT NOT NULL, provider_id TEXT NOT NULL, provider_version TEXT NOT NULL,
    target TEXT NOT NULL, start_time TEXT NOT NULL, end_time TEXT,
    status TEXT NOT NULL CHECK(status IN ('QUEUED','RUNNING','PAUSED','COMPLETED','FAILED','CANCELLED')),
    raw_output_reference TEXT, exit_status INTEGER,
    UNIQUE(workspace_id, id),
    FOREIGN KEY(workspace_id, chain_id) REFERENCES chain_runs(workspace_id, id),
    FOREIGN KEY(workspace_id, stage_id) REFERENCES chain_stages(workspace_id, id),
    FOREIGN KEY(workspace_id, raw_output_reference) REFERENCES evidence(workspace_id, id)
);
CREATE TABLE evidence (
    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id), provider_run_id TEXT NOT NULL,
    provider TEXT NOT NULL, target TEXT NOT NULL, timestamp TEXT NOT NULL,
    sha256 TEXT NOT NULL, media_type TEXT NOT NULL, relative_path TEXT NOT NULL, byte_count INTEGER NOT NULL,
    UNIQUE(workspace_id, id),
    FOREIGN KEY(workspace_id, provider_run_id) REFERENCES provider_runs(workspace_id, id)
);
CREATE TABLE observations (
    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id), asset_id TEXT NOT NULL,
    source_asset_id TEXT, provider_run_id TEXT, evidence_id TEXT, discovered_by TEXT NOT NULL,
    observed_value TEXT NOT NULL, timestamp TEXT NOT NULL, confidence TEXT NOT NULL,
    FOREIGN KEY(workspace_id, asset_id) REFERENCES assets(workspace_id, id),
    FOREIGN KEY(workspace_id, source_asset_id) REFERENCES assets(workspace_id, id),
    FOREIGN KEY(workspace_id, provider_run_id) REFERENCES provider_runs(workspace_id, id),
    FOREIGN KEY(workspace_id, evidence_id) REFERENCES evidence(workspace_id, id)
);
CREATE TABLE relationship_observations (
    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id), relationship_id TEXT NOT NULL,
    provider_run_id TEXT NOT NULL, evidence_id TEXT NOT NULL, timestamp TEXT NOT NULL,
    FOREIGN KEY(workspace_id, relationship_id) REFERENCES asset_relationships(workspace_id, id),
    FOREIGN KEY(workspace_id, provider_run_id) REFERENCES provider_runs(workspace_id, id),
    FOREIGN KEY(workspace_id, evidence_id) REFERENCES evidence(workspace_id, id)
);
CREATE TABLE events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id), timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL, payload TEXT NOT NULL CHECK(json_valid(payload))
);
CREATE TABLE audit_events (
    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id), timestamp TEXT NOT NULL,
    action TEXT NOT NULL, subject_id TEXT NOT NULL
);
CREATE INDEX observations_asset ON observations(workspace_id, asset_id);
CREATE INDEX events_workspace_sequence ON events(workspace_id, sequence);
CREATE INDEX chain_runs_workspace ON chain_runs(workspace_id, created_at);
