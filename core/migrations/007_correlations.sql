-- Milestone 6 (Issue #67): explicit, evidence-backed, reviewable correlation.
--
-- A correlation is an analyst-controlled claim that two distinct canonical assets
-- (e.g. a Username and an EmailAddress) may refer to the same real-world subject.
-- It is deliberately separate from canonical deduplication: it never merges,
-- rewrites, or deletes assets, observations, or relationships. Every correlation
-- cites observations (and therefore evidence) for both assets, carries a basis and a
-- confidence, starts PROPOSED, and changes state only through an explicit review
-- that is appended to correlation_reviews (reversible, never silently edited).
CREATE TABLE correlations (
    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    left_asset_id TEXT NOT NULL, right_asset_id TEXT NOT NULL,
    basis TEXT NOT NULL CHECK(basis IN ('analyst_review','shared_identifier','shared_public_record')),
    confidence TEXT NOT NULL CHECK(confidence IN ('LOW','MEDIUM','HIGH')),
    status TEXT NOT NULL CHECK(status IN ('PROPOSED','CONFIRMED','REJECTED','RETRACTED')),
    rationale TEXT NOT NULL CHECK(length(rationale) BETWEEN 1 AND 1024),
    observation_ids TEXT NOT NULL CHECK(json_valid(observation_ids)),
    evidence_ids TEXT NOT NULL CHECK(json_valid(evidence_ids)),
    created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    CHECK(left_asset_id < right_asset_id),
    UNIQUE(workspace_id, id),
    UNIQUE(workspace_id, left_asset_id, right_asset_id),
    FOREIGN KEY(workspace_id, left_asset_id) REFERENCES assets(workspace_id, id),
    FOREIGN KEY(workspace_id, right_asset_id) REFERENCES assets(workspace_id, id)
);
CREATE TABLE correlation_reviews (
    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    correlation_id TEXT NOT NULL,
    from_status TEXT, to_status TEXT NOT NULL,
    note TEXT NOT NULL CHECK(length(note) <= 1024),
    actor TEXT NOT NULL, timestamp TEXT NOT NULL,
    FOREIGN KEY(workspace_id, correlation_id) REFERENCES correlations(workspace_id, id)
);
CREATE INDEX correlation_reviews_by_correlation ON correlation_reviews(correlation_id, timestamp);
