-- Milestone 6 (OSINT foundation): OSINT account relationships and per-run
-- observation metadata.
--
-- 1. Allow the `has_account` and `profile_url` relationship types. SQLite cannot alter
--    a CHECK constraint in place, so rebuild asset_relationships (same technique as
--    003). This migration runs with foreign_keys temporarily disabled (see migrate()).
-- 2. Add a nullable JSON `metadata` column to observations so a provider can keep
--    per-run facts (upstream status, platform, bounded public profile metadata)
--    separate from the deduplicated canonical asset. Existing rows stay NULL.
CREATE TABLE asset_relationships_new (
    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    source_asset_id TEXT NOT NULL, destination_asset_id TEXT NOT NULL,
    relationship_type TEXT NOT NULL CHECK(relationship_type IN
      ('has_subdomain','resolves_to','ptr_record','exposes','serves','has_endpoint',
       'uses_technology','has_account','profile_url')),
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

ALTER TABLE observations ADD COLUMN metadata TEXT CHECK(metadata IS NULL OR json_valid(metadata));
