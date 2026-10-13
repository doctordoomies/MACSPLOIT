-- Milestone 6 (Domain / public-infrastructure OSINT, Issue #66): passive
-- relationship types.
--
-- `has_email` (Domain -> EmailAddress reported by a public source), `has_nameserver`
-- (Domain -> nameserver host from the registry's RDAP record), and `observed_ip`
-- (host/Domain -> IPAddress associated by a passive source; MACSPLOIT did not
-- resolve it, so this is deliberately distinct from `resolves_to`). SQLite cannot
-- alter a CHECK constraint in place, so rebuild asset_relationships (same technique
-- as 003/004). Runs with foreign_keys temporarily disabled (see migrate()).
CREATE TABLE asset_relationships_new (
    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    source_asset_id TEXT NOT NULL, destination_asset_id TEXT NOT NULL,
    relationship_type TEXT NOT NULL CHECK(relationship_type IN
      ('has_subdomain','resolves_to','ptr_record','exposes','serves','has_endpoint',
       'uses_technology','has_account','profile_url','has_email','has_nameserver',
       'observed_ip')),
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
