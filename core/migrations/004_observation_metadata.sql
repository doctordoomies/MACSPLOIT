-- M1.5: preserve provider/run-specific normalized discovery facts on the
-- Observation itself. Existing observations default to an empty object so older
-- workspaces migrate without losing assets/provenance.
ALTER TABLE observations
    ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}'
    CHECK(
        json_valid(metadata)
        AND CASE WHEN json_valid(metadata) THEN json_type(metadata) = 'object' ELSE 0 END
    );
