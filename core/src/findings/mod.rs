//! Durable analyst Findings (Milestone 2/4 foundation, Issue #76, parent #68).
//!
//! A Finding is a reviewable **security conclusion** an analyst draws from evidence. It
//! is deliberately distinct from the records it builds on:
//!
//! * **Observation** — a provider-reported fact ("what the tool saw").
//! * **Evidence** — the retained source material supporting an observation.
//! * **Finding** — "what security conclusion does the analyst draw from that evidence?"
//!
//! A Finding **references** durable records (affected canonical assets, evidence, and the
//! source run/provider when seeded from a result); it never copies raw provider stdout
//! into its text. **Severity, confidence, and lifecycle status are three independent
//! typed dimensions** — never collapsed. Lifecycle transitions and every link are
//! validated by the core (Swift is never the authority); history is append-only and
//! survives restart. No provider, parser, or chain creates a Finding — only an explicit
//! analyst action does. This slice is manual/analyst creation (optionally seeded from a
//! durable result); reviewed scanner-proposed findings come later.

use crate::{
    assets::Id,
    database::{audit, emit, encoded, Store},
    error::{CoreError, Result},
    events::EventType,
};
use rusqlite::{params, TransactionBehavior};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;

/// Impact dimension — how bad it is if real. Independent of confidence and status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    #[default]
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

/// How sure the analyst is that the finding is real. Separate from Observation
/// confidence (a provider's self-report); a Finding's confidence is the analyst's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingConfidence {
    #[default]
    Low,
    Medium,
    High,
    Confirmed,
}

/// Where the finding is in its security-testing lifecycle. Independent of severity and
/// confidence. Transitions are validated by [`FindingStatus::can_transition_to`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingStatus {
    Draft,
    Open,
    Confirmed,
    Informational,
    FalsePositive,
    Resolved,
    RetestPassed,
}

impl FindingStatus {
    /// Statuses a finding may be created in (a stub, a real open finding, a confirmed
    /// import, or a purely informational note). Terminal-ish states are reached only by
    /// an explicit transition with a recorded note.
    pub fn is_valid_initial(self) -> bool {
        matches!(
            self,
            Self::Draft | Self::Open | Self::Confirmed | Self::Informational
        )
    }

    /// Allowed lifecycle transitions. A no-op (same status) is not a transition.
    /// Kept deliberately small — a reviewable security lifecycle, not a workflow engine.
    pub fn can_transition_to(self, to: Self) -> bool {
        use FindingStatus::*;
        matches!(
            (self, to),
            (Draft, Open)
                | (Draft, Informational)
                | (Draft, FalsePositive)
                | (Open, Confirmed)
                | (Open, Informational)
                | (Open, FalsePositive)
                | (Open, Resolved)
                | (Confirmed, Resolved)
                | (Confirmed, FalsePositive)
                | (Informational, Open)
                | (Informational, FalsePositive)
                | (FalsePositive, Open)
                | (Resolved, RetestPassed)
                | (Resolved, Open)
                | (RetestPassed, Open)
        )
    }
}

/// One append-only history entry for a finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FindingHistoryEntry {
    pub id: Id,
    pub kind: String,
    pub from_value: Option<String>,
    pub to_value: Option<String>,
    pub note: String,
    pub actor: String,
    pub timestamp: String,
}

/// An affected canonical asset link (at most one `is_primary` per finding).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AffectedAsset {
    pub asset_id: Id,
    pub is_primary: bool,
}

/// A durable finding with its links and history (the read shape the UI/reports consume).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub id: Id,
    pub workspace_id: Id,
    pub title: String,
    pub severity: Severity,
    pub confidence: FindingConfidence,
    pub status: FindingStatus,
    pub description: String,
    pub reproduction: String,
    pub remediation: String,
    /// Immutable source attribution when seeded from a provider result (else None).
    pub source_provider: Option<String>,
    pub source_run_id: Option<Id>,
    pub tags: Vec<String>,
    pub cwe_ids: Vec<String>,
    pub cve_ids: Vec<String>,
    pub affected_assets: Vec<AffectedAsset>,
    pub evidence_ids: Vec<Id>,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
    /// Append-only, oldest first (the first entry is CREATED).
    pub history: Vec<FindingHistoryEntry>,
}

/// Analyst input to create a finding. Only factual references (asset/evidence/source)
/// are ever prefilled by the "Create Finding from a result" action; the analyst writes
/// the conclusion (title/severity/confidence/status/text).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct NewFinding {
    pub title: String,
    pub severity: Severity,
    pub confidence: FindingConfidence,
    #[serde(default)]
    pub status: Option<FindingStatus>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub reproduction: String,
    #[serde(default)]
    pub remediation: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub cwe_ids: Vec<String>,
    #[serde(default)]
    pub cve_ids: Vec<String>,
    /// The primary affected asset (optional; required to be in-workspace if given).
    #[serde(default)]
    pub primary_asset_id: Option<Id>,
    /// Additional affected assets (future multi-asset findings; all in-workspace).
    #[serde(default)]
    pub additional_asset_ids: Vec<Id>,
    /// Evidence references to attach at creation (in-workspace, deduplicated).
    #[serde(default)]
    pub evidence_ids: Vec<Id>,
    /// Immutable source attribution (set by the create-from-result action only).
    #[serde(default)]
    pub source_provider: Option<String>,
    #[serde(default)]
    pub source_run_id: Option<Id>,
}

/// Analyst edits to a finding's own fields. Absent fields are unchanged. Status is NOT
/// here (use [`Store::set_finding_status`]); source attribution is immutable.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FindingEdit {
    pub title: Option<String>,
    pub severity: Option<Severity>,
    pub confidence: Option<FindingConfidence>,
    pub description: Option<String>,
    pub reproduction: Option<String>,
    pub remediation: Option<String>,
    pub tags: Option<Vec<String>>,
    pub cwe_ids: Option<Vec<String>>,
    pub cve_ids: Option<Vec<String>>,
}

pub const MAX_TITLE_BYTES: usize = 200;
pub const MAX_TEXT_BYTES: usize = 8192;
pub const MAX_NOTE_BYTES: usize = 1024;
pub const MAX_TAGS: usize = 24;
pub const MAX_TAG_BYTES: usize = 48;
pub const MAX_IDS: usize = 32;
pub const MAX_ID_BYTES: usize = 32;
pub const MAX_AFFECTED_ASSETS: usize = 20;
pub const MAX_EVIDENCE_LINKS: usize = 50;
pub const MAX_FINDINGS: i64 = 2000;
const ACTOR: &str = "Analyst";

/// Strip control chars, trim, and require 1..=max bytes.
fn required_text(value: &str, field: &str, max: usize) -> Result<String> {
    let cleaned = clean(value);
    if cleaned.is_empty() || cleaned.len() > max {
        return Err(CoreError::new(
            "InvalidRequest",
            &format!("The {field} must be 1-{max} bytes."),
        ));
    }
    Ok(cleaned)
}

/// Strip control chars and trim; allow empty; require <=max bytes.
fn optional_text(value: &str, field: &str, max: usize) -> Result<String> {
    let cleaned = clean(value);
    if cleaned.len() > max {
        return Err(CoreError::new(
            "InvalidRequest",
            &format!("The {field} must be at most {max} bytes."),
        ));
    }
    Ok(cleaned)
}

fn clean(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_owned()
}

/// Bounded, cleaned, de-duplicated tag list.
fn clean_tags(tags: &[String]) -> Result<Vec<String>> {
    if tags.len() > MAX_TAGS {
        return Err(CoreError::new(
            "InvalidRequest",
            &format!("At most {MAX_TAGS} tags are allowed."),
        ));
    }
    let mut out: Vec<String> = Vec::new();
    for tag in tags {
        let tag = clean(tag);
        if tag.is_empty() || tag.len() > MAX_TAG_BYTES {
            return Err(CoreError::new(
                "InvalidRequest",
                &format!("Each tag must be 1-{MAX_TAG_BYTES} bytes."),
            ));
        }
        if !out.contains(&tag) {
            out.push(tag);
        }
    }
    Ok(out)
}

/// Validate and normalize CVE/CWE identifiers. A syntactically valid id does not prove
/// applicability — it is only stored in the right shape.
fn clean_identifiers(ids: &[String], kind: Identifier) -> Result<Vec<String>> {
    if ids.len() > MAX_IDS {
        return Err(CoreError::new(
            "InvalidRequest",
            &format!("At most {MAX_IDS} identifiers are allowed."),
        ));
    }
    let mut out: Vec<String> = Vec::new();
    for raw in ids {
        let id = clean(raw).to_uppercase();
        if id.len() > MAX_ID_BYTES || !kind.is_valid(&id) {
            return Err(CoreError::new(
                "InvalidRequest",
                &format!(
                    "An identifier does not match the bounded {} format.",
                    kind.label()
                ),
            ));
        }
        if !out.contains(&id) {
            out.push(id);
        }
    }
    Ok(out)
}

#[derive(Clone, Copy)]
enum Identifier {
    Cve,
    Cwe,
}
impl Identifier {
    fn label(self) -> &'static str {
        match self {
            Self::Cve => "CVE",
            Self::Cwe => "CWE",
        }
    }
    /// CVE-YYYY-NNNN+ ; CWE-NNN+ (already uppercased). No regex dependency.
    fn is_valid(self, id: &str) -> bool {
        match self {
            Self::Cve => {
                let Some(rest) = id.strip_prefix("CVE-") else {
                    return false;
                };
                let mut parts = rest.split('-');
                let (Some(year), Some(seq), None) = (parts.next(), parts.next(), parts.next())
                else {
                    return false;
                };
                year.len() == 4
                    && year.bytes().all(|b| b.is_ascii_digit())
                    && seq.len() >= 4
                    && seq.bytes().all(|b| b.is_ascii_digit())
            }
            Self::Cwe => id
                .strip_prefix("CWE-")
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())),
        }
    }
}

fn stored_json<T: DeserializeOwned>(text: String) -> rusqlite::Result<T> {
    serde_json::from_str(&text).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}
fn stored_enum<T: DeserializeOwned>(text: String) -> rusqlite::Result<T> {
    stored_json(serde_json::Value::String(text).to_string())
}
fn parse_id(s: String) -> rusqlite::Result<Id> {
    Id::parse_str(&s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}

fn load(conn: &rusqlite::Connection, workspace: Id, filter: Option<Id>) -> Result<Vec<Finding>> {
    let mut statement = conn.prepare(
        "SELECT id,title,severity,confidence,status,description,reproduction,remediation,
                source_provider,source_run_id,tags,cwe_ids,cve_ids,created_by,created_at,updated_at
         FROM findings WHERE workspace_id=?1 AND (?2 IS NULL OR id=?2) ORDER BY created_at,id",
    )?;
    let rows = statement.query_map(
        params![workspace.to_string(), filter.map(|f| f.to_string())],
        |row| {
            Ok(Finding {
                id: parse_id(row.get(0)?)?,
                workspace_id: workspace,
                title: row.get(1)?,
                severity: stored_enum(row.get(2)?)?,
                confidence: stored_enum(row.get(3)?)?,
                status: stored_enum(row.get(4)?)?,
                description: row.get(5)?,
                reproduction: row.get(6)?,
                remediation: row.get(7)?,
                source_provider: row.get(8)?,
                source_run_id: row.get::<_, Option<String>>(9)?.map(parse_id).transpose()?,
                tags: stored_json(row.get(10)?)?,
                cwe_ids: stored_json(row.get(11)?)?,
                cve_ids: stored_json(row.get(12)?)?,
                affected_assets: Vec::new(),
                evidence_ids: Vec::new(),
                created_by: row.get(13)?,
                created_at: row.get(14)?,
                updated_at: row.get(15)?,
                history: Vec::new(),
            })
        },
    )?;
    let mut findings = rows.collect::<rusqlite::Result<Vec<_>>>()?;

    let mut assets = conn.prepare(
        "SELECT asset_id,is_primary FROM finding_assets WHERE workspace_id=?1 AND finding_id=?2
         ORDER BY is_primary DESC,linked_at,asset_id",
    )?;
    let mut evidence = conn.prepare(
        "SELECT evidence_id FROM finding_evidence WHERE workspace_id=?1 AND finding_id=?2
         ORDER BY linked_at,evidence_id",
    )?;
    let mut history = conn.prepare(
        "SELECT id,kind,from_value,to_value,note,actor,timestamp FROM finding_history
         WHERE workspace_id=?1 AND finding_id=?2 ORDER BY timestamp,rowid",
    )?;
    for finding in &mut findings {
        let key = params![workspace.to_string(), finding.id.to_string()];
        finding.affected_assets = assets
            .query_map(key, |row| {
                Ok(AffectedAsset {
                    asset_id: parse_id(row.get(0)?)?,
                    is_primary: row.get::<_, i64>(1)? != 0,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        finding.evidence_ids = evidence
            .query_map(key, |row| parse_id(row.get(0)?))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        finding.history = history
            .query_map(key, |row| {
                Ok(FindingHistoryEntry {
                    id: parse_id(row.get(0)?)?,
                    kind: row.get(1)?,
                    from_value: row.get(2)?,
                    to_value: row.get(3)?,
                    note: row.get(4)?,
                    actor: row.get(5)?,
                    timestamp: row.get(6)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
    }
    Ok(findings)
}

/// Every finding in a workspace (with links and history), oldest first.
pub fn findings_in(conn: &rusqlite::Connection, workspace: Id) -> Result<Vec<Finding>> {
    load(conn, workspace, None)
}

#[allow(clippy::too_many_arguments)] // an internal history-row writer; args mirror the columns
fn record_history(
    tx: &rusqlite::Transaction,
    workspace: Id,
    finding: Id,
    kind: &str,
    from: Option<&str>,
    to: Option<&str>,
    note: &str,
    now: &str,
) -> Result<()> {
    tx.execute(
        "INSERT INTO finding_history VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![
            Id::new_v4().to_string(),
            workspace.to_string(),
            finding.to_string(),
            kind,
            from,
            to,
            note,
            ACTOR,
            now
        ],
    )?;
    Ok(())
}

fn asset_exists(tx: &rusqlite::Transaction, workspace: Id, asset: Id) -> Result<bool> {
    Ok(tx
        .prepare("SELECT 1 FROM assets WHERE workspace_id=?1 AND id=?2")?
        .exists(params![workspace.to_string(), asset.to_string()])?)
}
fn evidence_exists(tx: &rusqlite::Transaction, workspace: Id, evidence: Id) -> Result<bool> {
    Ok(tx
        .prepare("SELECT 1 FROM evidence WHERE workspace_id=?1 AND id=?2")?
        .exists(params![workspace.to_string(), evidence.to_string()])?)
}

impl Store {
    /// Create a durable finding from analyst input (optionally seeded from a result's
    /// factual references). Validates bounds, enum values, and that every referenced
    /// asset/evidence exists in THIS workspace; cross-workspace references are rejected.
    pub fn create_finding(&self, workspace: Id, new: NewFinding) -> Result<Finding> {
        let title = required_text(&new.title, "title", MAX_TITLE_BYTES)?;
        let description = optional_text(&new.description, "description", MAX_TEXT_BYTES)?;
        let reproduction = optional_text(&new.reproduction, "reproduction", MAX_TEXT_BYTES)?;
        let remediation = optional_text(&new.remediation, "remediation", MAX_TEXT_BYTES)?;
        let tags = clean_tags(&new.tags)?;
        let cwe_ids = clean_identifiers(&new.cwe_ids, Identifier::Cwe)?;
        let cve_ids = clean_identifiers(&new.cve_ids, Identifier::Cve)?;
        let status = new.status.unwrap_or(FindingStatus::Open);
        if !status.is_valid_initial() {
            return Err(CoreError::new(
                "InvalidRequest",
                "A finding may only be created as DRAFT, OPEN, CONFIRMED, or INFORMATIONAL.",
            ));
        }
        let source_provider = match &new.source_provider {
            Some(p) => Some(required_text(p, "source provider", 128)?),
            None => None,
        };

        if new.additional_asset_ids.len() > MAX_AFFECTED_ASSETS
            || new.evidence_ids.len() > MAX_EVIDENCE_LINKS
        {
            return Err(CoreError::new(
                "InvalidRequest",
                "The supplied asset/evidence reference list exceeds its limit.",
            ));
        }
        // Collect affected assets: primary first, then additional, de-duplicated.
        let mut affected: Vec<(Id, bool)> = Vec::new();
        if let Some(primary) = new.primary_asset_id {
            affected.push((primary, true));
        }
        for asset in new.additional_asset_ids {
            if !affected.iter().any(|(a, _)| *a == asset) {
                affected.push((asset, false));
            }
        }
        if affected.len() > MAX_AFFECTED_ASSETS {
            return Err(CoreError::new(
                "InvalidRequest",
                &format!("A finding may reference at most {MAX_AFFECTED_ASSETS} assets."),
            ));
        }
        let mut evidence: Vec<Id> = Vec::new();
        for id in new.evidence_ids {
            if !evidence.contains(&id) {
                evidence.push(id);
            }
        }
        if evidence.len() > MAX_EVIDENCE_LINKS {
            return Err(CoreError::new(
                "InvalidRequest",
                &format!("A finding may reference at most {MAX_EVIDENCE_LINKS} evidence records."),
            ));
        }

        let mut conn = self.connect(workspace)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: i64 = tx.query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))?;
        if count >= MAX_FINDINGS {
            return Err(CoreError::new(
                "BudgetExceeded",
                &format!("The finding limit is {MAX_FINDINGS} per workspace."),
            ));
        }
        for (asset, _) in &affected {
            if !asset_exists(&tx, workspace, *asset)? {
                return Err(CoreError::new(
                    "AssetNotFound",
                    "An affected asset does not exist in this workspace.",
                ));
            }
        }
        for id in &evidence {
            if !evidence_exists(&tx, workspace, *id)? {
                return Err(CoreError::new(
                    "InvalidRequest",
                    "A referenced evidence record does not exist in this workspace.",
                ));
            }
        }
        // Source run, when given, must exist in this workspace.
        if let Some(run) = new.source_run_id {
            use rusqlite::OptionalExtension;
            let provider: Option<String> = tx
                .query_row(
                    "SELECT provider_id FROM provider_runs WHERE workspace_id=?1 AND id=?2",
                    params![workspace.to_string(), run.to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            if provider.is_none() {
                return Err(CoreError::new(
                    "InvalidRequest",
                    "The source run does not exist in this workspace.",
                ));
            }
            if source_provider
                .as_ref()
                .is_some_and(|source| Some(source) != provider.as_ref())
            {
                return Err(CoreError::new(
                    "InvalidRequest",
                    "The source provider does not match the referenced run.",
                ));
            }
        }

        let id = Id::new_v4();
        let now = crate::now();
        // Column order: id, workspace_id, title, severity, confidence, status,
        // description, reproduction, remediation, source_provider, source_run_id,
        // tags, cwe_ids, cve_ids, created_by, created_at, updated_at.
        tx.execute(
            "INSERT INTO findings VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?16)",
            params![
                id.to_string(),
                workspace.to_string(),
                title,
                encoded(&new.severity),
                encoded(&new.confidence),
                encoded(&status),
                description,
                reproduction,
                remediation,
                source_provider,
                new.source_run_id.map(|r| r.to_string()),
                serde_json::to_string(&tags)?,
                serde_json::to_string(&cwe_ids)?,
                serde_json::to_string(&cve_ids)?,
                ACTOR,
                now,
            ],
        )?;
        for (asset, is_primary) in &affected {
            tx.execute(
                "INSERT INTO finding_assets VALUES(?1,?2,?3,?4,?5)",
                params![
                    workspace.to_string(),
                    id.to_string(),
                    asset.to_string(),
                    i64::from(*is_primary),
                    now
                ],
            )?;
        }
        for evidence_id in &evidence {
            tx.execute(
                "INSERT INTO finding_evidence VALUES(?1,?2,?3,?4)",
                params![
                    workspace.to_string(),
                    id.to_string(),
                    evidence_id.to_string(),
                    now
                ],
            )?;
        }
        record_history(
            &tx,
            workspace,
            id,
            "CREATED",
            None,
            Some(&encoded(&status)),
            "Finding created.",
            &now,
        )?;
        emit(
            &tx,
            workspace,
            EventType::FindingCreated,
            json!({"finding_id": id, "severity": new.severity, "status": status}),
        )?;
        audit(&tx, workspace, "FindingCreated", id)?;
        let finding = load(&tx, workspace, Some(id))?
            .pop()
            .ok_or_else(|| CoreError::new("DatabaseError", "Finding was not stored."))?;
        tx.commit()?;
        Ok(finding)
    }

    /// Edit analyst-controlled fields atomically. Status and source attribution are not
    /// editable here. Severity/confidence changes are recorded in history.
    pub fn update_finding(&self, workspace: Id, finding: Id, edit: FindingEdit) -> Result<Finding> {
        let mut conn = self.connect(workspace)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load(&tx, workspace, Some(finding))?.pop().ok_or_else(|| {
            CoreError::new(
                "FindingNotFound",
                "Finding does not exist in this workspace.",
            )
        })?;
        let now = crate::now();

        let title = match &edit.title {
            Some(t) => required_text(t, "title", MAX_TITLE_BYTES)?,
            None => current.title.clone(),
        };
        let severity = edit.severity.unwrap_or(current.severity);
        let confidence = edit.confidence.unwrap_or(current.confidence);
        let description = match &edit.description {
            Some(t) => optional_text(t, "description", MAX_TEXT_BYTES)?,
            None => current.description.clone(),
        };
        let reproduction = match &edit.reproduction {
            Some(t) => optional_text(t, "reproduction", MAX_TEXT_BYTES)?,
            None => current.reproduction.clone(),
        };
        let remediation = match &edit.remediation {
            Some(t) => optional_text(t, "remediation", MAX_TEXT_BYTES)?,
            None => current.remediation.clone(),
        };
        let tags = match &edit.tags {
            Some(t) => clean_tags(t)?,
            None => current.tags.clone(),
        };
        let cwe_ids = match &edit.cwe_ids {
            Some(t) => clean_identifiers(t, Identifier::Cwe)?,
            None => current.cwe_ids.clone(),
        };
        let cve_ids = match &edit.cve_ids {
            Some(t) => clean_identifiers(t, Identifier::Cve)?,
            None => current.cve_ids.clone(),
        };

        tx.execute(
            "UPDATE findings SET title=?1,severity=?2,confidence=?3,description=?4,reproduction=?5,
                remediation=?6,tags=?7,cwe_ids=?8,cve_ids=?9,updated_at=?10
             WHERE workspace_id=?11 AND id=?12",
            params![
                title,
                encoded(&severity),
                encoded(&confidence),
                description,
                reproduction,
                remediation,
                serde_json::to_string(&tags)?,
                serde_json::to_string(&cwe_ids)?,
                serde_json::to_string(&cve_ids)?,
                now,
                workspace.to_string(),
                finding.to_string()
            ],
        )?;
        if severity != current.severity {
            record_history(
                &tx,
                workspace,
                finding,
                "SEVERITY",
                Some(&encoded(&current.severity)),
                Some(&encoded(&severity)),
                "Severity changed.",
                &now,
            )?;
        }
        if confidence != current.confidence {
            record_history(
                &tx,
                workspace,
                finding,
                "CONFIDENCE",
                Some(&encoded(&current.confidence)),
                Some(&encoded(&confidence)),
                "Confidence changed.",
                &now,
            )?;
        }
        record_history(
            &tx,
            workspace,
            finding,
            "EDITED",
            None,
            None,
            "Finding edited.",
            &now,
        )?;
        emit(
            &tx,
            workspace,
            EventType::FindingUpdated,
            json!({"finding_id": finding}),
        )?;
        audit(&tx, workspace, "FindingUpdated", finding)?;
        let updated = load(&tx, workspace, Some(finding))?
            .pop()
            .ok_or_else(|| CoreError::new("DatabaseError", "Finding was not stored."))?;
        tx.commit()?;
        Ok(updated)
    }

    /// Apply a validated lifecycle transition, appended to history with a note.
    pub fn set_finding_status(
        &self,
        workspace: Id,
        finding: Id,
        to: FindingStatus,
        note: &str,
    ) -> Result<Finding> {
        let note = required_text(note, "status note", MAX_NOTE_BYTES)?;
        let mut conn = self.connect(workspace)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load(&tx, workspace, Some(finding))?.pop().ok_or_else(|| {
            CoreError::new(
                "FindingNotFound",
                "Finding does not exist in this workspace.",
            )
        })?;
        if !current.status.can_transition_to(to) {
            return Err(CoreError::new(
                "InvalidTransition",
                "That lifecycle transition is not allowed from the finding's current status.",
            ));
        }
        let now = crate::now();
        tx.execute(
            "UPDATE findings SET status=?1,updated_at=?2 WHERE workspace_id=?3 AND id=?4",
            params![
                encoded(&to),
                now,
                workspace.to_string(),
                finding.to_string()
            ],
        )?;
        record_history(
            &tx,
            workspace,
            finding,
            "STATUS",
            Some(&encoded(&current.status)),
            Some(&encoded(&to)),
            &note,
            &now,
        )?;
        emit(
            &tx,
            workspace,
            EventType::FindingStatusChanged,
            json!({"finding_id": finding, "from": current.status, "to": to}),
        )?;
        audit(&tx, workspace, "FindingStatusChanged", finding)?;
        let updated = load(&tx, workspace, Some(finding))?
            .pop()
            .ok_or_else(|| CoreError::new("DatabaseError", "Finding was not stored."))?;
        tx.commit()?;
        Ok(updated)
    }

    /// Attach an evidence record (idempotent per finding; same-workspace only).
    pub fn link_finding_evidence(
        &self,
        workspace: Id,
        finding: Id,
        evidence_id: Id,
    ) -> Result<Finding> {
        self.change_finding_evidence(workspace, finding, evidence_id, true)
    }

    /// Detach an evidence record (the Evidence itself is never deleted).
    pub fn unlink_finding_evidence(
        &self,
        workspace: Id,
        finding: Id,
        evidence_id: Id,
    ) -> Result<Finding> {
        self.change_finding_evidence(workspace, finding, evidence_id, false)
    }

    fn change_finding_evidence(
        &self,
        workspace: Id,
        finding: Id,
        evidence_id: Id,
        link: bool,
    ) -> Result<Finding> {
        let mut conn = self.connect(workspace)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load(&tx, workspace, Some(finding))?.pop().ok_or_else(|| {
            CoreError::new(
                "FindingNotFound",
                "Finding does not exist in this workspace.",
            )
        })?;
        let now = crate::now();
        if link {
            if !evidence_exists(&tx, workspace, evidence_id)? {
                return Err(CoreError::new(
                    "InvalidRequest",
                    "That evidence record does not exist in this workspace.",
                ));
            }
            if current.evidence_ids.contains(&evidence_id) {
                // Idempotent: already linked, nothing to change.
                tx.commit()?;
                return Ok(current);
            }
            if current.evidence_ids.len() >= MAX_EVIDENCE_LINKS {
                return Err(CoreError::new(
                    "BudgetExceeded",
                    &format!(
                        "A finding may reference at most {MAX_EVIDENCE_LINKS} evidence records."
                    ),
                ));
            }
            tx.execute(
                "INSERT INTO finding_evidence VALUES(?1,?2,?3,?4)",
                params![
                    workspace.to_string(),
                    finding.to_string(),
                    evidence_id.to_string(),
                    now
                ],
            )?;
            record_history(
                &tx,
                workspace,
                finding,
                "EVIDENCE_LINKED",
                None,
                Some(&evidence_id.to_string()),
                "Evidence linked.",
                &now,
            )?;
        } else {
            let removed = tx.execute(
                "DELETE FROM finding_evidence WHERE workspace_id=?1 AND finding_id=?2 AND evidence_id=?3",
                params![workspace.to_string(), finding.to_string(), evidence_id.to_string()],
            )?;
            if removed == 0 {
                tx.commit()?;
                return Ok(current);
            }
            record_history(
                &tx,
                workspace,
                finding,
                "EVIDENCE_UNLINKED",
                Some(&evidence_id.to_string()),
                None,
                "Evidence unlinked.",
                &now,
            )?;
        }
        tx.execute(
            "UPDATE findings SET updated_at=?1 WHERE workspace_id=?2 AND id=?3",
            params![now, workspace.to_string(), finding.to_string()],
        )?;
        emit(
            &tx,
            workspace,
            EventType::FindingUpdated,
            json!({"finding_id": finding, "evidence_linked": link}),
        )?;
        let updated = load(&tx, workspace, Some(finding))?
            .pop()
            .ok_or_else(|| CoreError::new("DatabaseError", "Finding was not stored."))?;
        tx.commit()?;
        Ok(updated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_confidence_status_are_independent_types() {
        assert!(Severity::Critical > Severity::Low);
        assert!(FindingConfidence::Confirmed > FindingConfidence::Low);
        // Status has no ordering and no implied severity/confidence.
        assert!(FindingStatus::Open.is_valid_initial());
        assert!(!FindingStatus::Resolved.is_valid_initial());
    }

    #[test]
    fn only_documented_transitions_apply() {
        use FindingStatus::*;
        assert!(Open.can_transition_to(Confirmed));
        assert!(Open.can_transition_to(FalsePositive));
        assert!(Confirmed.can_transition_to(Resolved));
        assert!(Resolved.can_transition_to(RetestPassed));
        assert!(FalsePositive.can_transition_to(Open));
        assert!(!Open.can_transition_to(RetestPassed));
        assert!(!Open.can_transition_to(Open)); // no-op is not a transition
        assert!(!Draft.can_transition_to(Resolved));
        assert!(!RetestPassed.can_transition_to(Confirmed));
    }

    #[test]
    fn identifiers_validate_shape_only() {
        assert!(Identifier::Cve.is_valid("CVE-2021-44228"));
        assert!(Identifier::Cve.is_valid("CVE-2021-412345"));
        assert!(!Identifier::Cve.is_valid("CVE-21-1"));
        assert!(!Identifier::Cve.is_valid("CVE-2021-12")); // seq too short
        assert!(!Identifier::Cve.is_valid("2021-44228"));
        assert!(Identifier::Cwe.is_valid("CWE-79"));
        assert!(!Identifier::Cwe.is_valid("CWE-"));
        assert!(!Identifier::Cwe.is_valid("CWE-ab"));
        assert_eq!(
            clean_identifiers(
                &["cve-2021-44228".into(), "CVE-2021-44228".into()],
                Identifier::Cve
            )
            .unwrap(),
            vec!["CVE-2021-44228".to_string()]
        );
        assert!(clean_identifiers(&["nonsense".into()], Identifier::Cve).is_err());
    }

    #[test]
    fn text_fields_are_bounded_and_control_free() {
        assert_eq!(required_text("  a\u{0}b  ", "t", 200).unwrap(), "a b");
        assert!(required_text("   ", "t", 200).is_err());
        assert!(required_text(&"a".repeat(201), "t", 200).is_err());
        assert_eq!(optional_text("", "d", 10).unwrap(), "");
        assert!(optional_text(&"a".repeat(11), "d", 10).is_err());
        assert!(clean_tags(&vec!["x".into(); MAX_TAGS + 1]).is_err());
    }
}
