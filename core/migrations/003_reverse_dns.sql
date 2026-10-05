-- Milestone 1.4 follow-up: allow the `ptr_record` relationship type (reverse DNS).
-- SQLite cannot alter a CHECK constraint in place, so rebuild asset_relationships.
-- This migration runs with foreign_keys temporarily disabled (see migrate()), so the
-- relationship_observations FK that references this table survives the drop/rename.
CREATE TABLE asset_relationships_new (
    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    source_asset_id TEXT NOT NULL, destination_asset_id TEXT NOT NULL,
    relationship_type TEXT NOT NULL CHECK(relationship_type IN
      ('has_subdomain','resolves_to','ptr_record','exposes','serves','has_endpoint','uses_technology')),
    created_at TEXT NOT NULL, UNIQUE(workspace_id, id),
    UNIQUE(workspace_id, source_asset_id, destination_asset_id, relationship_type),
    FOREIGN KEY(workspace_id, source_asset_id) REFERENCES assets(workspace_id, id),
    FOREIGN KEY(workspace_id, destination_asset_id) REFERENCES assets(workspace_id, id)
);
INSERT INTO asset_relationships_new
    SELECT id, workspace_id, source_asset_id, destination_asset_id, relationship_type, created_at
    FROM asset_relationships;
DROP TABLE asset_relationships;
ALTER TABLE asset_relationships_new RENAME TO asset_relationships;
