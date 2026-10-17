-- Milestone 2/4 foundation (Issue #76, parent #68): durable analyst Findings.
--
-- A Finding is a reviewable SECURITY CONCLUSION an analyst draws from evidence. It is
-- deliberately distinct from the two things it builds on:
--   * Observation — a provider-reported fact ("what the tool saw").
--   * Evidence — the retained source material supporting an observation.
--   * Finding — "what security conclusion does the analyst draw from that evidence?"
-- Findings REFERENCE durable records (affected assets, evidence, the source run/provider);
-- they never copy raw provider stdout into their text. Severity, confidence, and
-- lifecycle status are three INDEPENDENT typed dimensions. Lifecycle transitions and all
-- links are validated by the Rust core; history is append-only. No provider, parser, or
-- chain creates a Finding — only an explicit analyst action does (this slice is manual
-- creation; reviewed scanner-proposed findings come later).
CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    title TEXT NOT NULL CHECK(length(title) BETWEEN 1 AND 200),
    severity TEXT NOT NULL CHECK(severity IN ('INFORMATIONAL','LOW','MEDIUM','HIGH','CRITICAL')),
    confidence TEXT NOT NULL CHECK(confidence IN ('LOW','MEDIUM','HIGH','CONFIRMED')),
    status TEXT NOT NULL CHECK(status IN ('DRAFT','OPEN','CONFIRMED','INFORMATIONAL','FALSE_POSITIVE','RESOLVED','RETEST_PASSED')),
    description TEXT NOT NULL CHECK(length(description) <= 8192),
    reproduction TEXT NOT NULL CHECK(length(reproduction) <= 8192),
    remediation TEXT NOT NULL CHECK(length(remediation) <= 8192),
    -- Immutable provenance when the finding was seeded from a provider result (both NULL
    -- for a purely manual finding). Kept separate from the analyst-written text above so
    -- source attribution is never confused with the analyst's conclusion.
    source_provider TEXT CHECK(source_provider IS NULL OR length(source_provider) <= 128),
    source_run_id TEXT,
    -- Bounded JSON string arrays (count/length enforced in the core, shape enforced here).
    tags TEXT NOT NULL CHECK(json_valid(tags)),
    cwe_ids TEXT NOT NULL CHECK(json_valid(cwe_ids)),
    cve_ids TEXT NOT NULL CHECK(json_valid(cve_ids)),
    created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    UNIQUE(workspace_id, id)
);

-- One-or-many affected canonical assets. At most one row per finding is the primary
-- (enforced in the core); the primary drives UI presentation. Same-workspace only.
CREATE TABLE finding_assets (
    workspace_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    is_primary INTEGER NOT NULL DEFAULT 0 CHECK(is_primary IN (0,1)),
    linked_at TEXT NOT NULL,
    PRIMARY KEY(finding_id, asset_id),
    FOREIGN KEY(workspace_id, finding_id) REFERENCES findings(workspace_id, id),
    FOREIGN KEY(workspace_id, asset_id) REFERENCES assets(workspace_id, id)
);
CREATE INDEX finding_assets_by_finding ON finding_assets(finding_id);

-- Multiple Evidence references per finding. Evidence stays independently integrity-checked
-- by the existing Evidence system; unlinking one never corrupts the finding. Same-workspace.
CREATE TABLE finding_evidence (
    workspace_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    linked_at TEXT NOT NULL,
    PRIMARY KEY(finding_id, evidence_id),
    FOREIGN KEY(workspace_id, finding_id) REFERENCES findings(workspace_id, id),
    FOREIGN KEY(workspace_id, evidence_id) REFERENCES evidence(workspace_id, id)
);
CREATE INDEX finding_evidence_by_finding ON finding_evidence(finding_id);

-- Append-only history of significant analyst actions (creation, lifecycle transitions,
-- severity/confidence changes, edits, and link changes). Survives restart; never edited.
CREATE TABLE finding_history (
    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    finding_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('CREATED','STATUS','SEVERITY','CONFIDENCE','EDITED','EVIDENCE_LINKED','EVIDENCE_UNLINKED','ASSET_LINKED','ASSET_UNLINKED')),
    from_value TEXT, to_value TEXT,
    note TEXT NOT NULL CHECK(length(note) <= 1024),
    actor TEXT NOT NULL, timestamp TEXT NOT NULL,
    FOREIGN KEY(workspace_id, finding_id) REFERENCES findings(workspace_id, id)
);
CREATE INDEX finding_history_by_finding ON finding_history(finding_id, timestamp);
