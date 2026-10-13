//! Explicit, evidence-backed, reviewable correlation (Milestone 6, Issue #67).
//!
//! Canonical deduplication answers "is this the same asset?" (same type and
//! canonical identity — e.g. two providers reporting `api.example.test`). It is
//! automatic and never crosses identities. Correlation answers a different, much
//! weaker question: "might these two *different* assets refer to the same
//! real-world subject?" (e.g. `@octo` and `octo@example.test`, or two accounts on
//! different platforms). That claim is never inferred or applied automatically:
//!
//! * **Explicit** — created only by an analyst action (`propose_correlation`); no
//!   provider, parser, or chain ever creates one.
//! * **Evidence-backed / attributable** — it must cite at least one observation of
//!   each asset, and every cited observation must carry evidence; the evidence ids
//!   are recorded with the correlation.
//! * **Confidence-aware** — basis + confidence are required. A shared identifier
//!   (same handle on two platforms) is a weak signal and is capped at LOW.
//! * **Reviewable / reversible** — it starts PROPOSED and changes state only through
//!   an explicit review (confirm, reject, retract, reopen) that is appended to an
//!   immutable review log with the analyst's note.
//! * **Non-destructive** — assets, observations, relationships, and evidence are
//!   never merged, rewritten, or deleted by correlation.

use crate::{
    assets::Id,
    database::{audit, emit, Store},
    error::{CoreError, Result},
    events::EventType,
};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Why the analyst believes two assets may refer to one subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationBasis {
    /// The analyst reviewed the cited evidence and asserts the link.
    AnalystReview,
    /// The same identifier appears on both (e.g. one handle on two platforms).
    /// Weak: many people share handles. Capped at LOW confidence.
    SharedIdentifier,
    /// A public record cited in evidence names both (e.g. a profile listing the email).
    SharedPublicRecord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CorrelationConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CorrelationStatus {
    Proposed,
    Confirmed,
    Rejected,
    Retracted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDecision {
    Confirm,
    Reject,
    Retract,
    Reopen,
}

impl ReviewDecision {
    /// Allowed transitions. Anything else is refused (no silent edits).
    fn apply(self, from: CorrelationStatus) -> Option<CorrelationStatus> {
        use CorrelationStatus::*;
        match (self, from) {
            (Self::Confirm, Proposed) => Some(Confirmed),
            (Self::Reject, Proposed) => Some(Rejected),
            (Self::Retract, Confirmed) => Some(Retracted),
            (Self::Reopen, Rejected | Retracted) => Some(Proposed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CorrelationReview {
    pub id: Id,
    pub from_status: Option<CorrelationStatus>,
    pub to_status: CorrelationStatus,
    pub note: String,
    pub actor: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Correlation {
    pub id: Id,
    pub workspace_id: Id,
    pub left_asset_id: Id,
    pub right_asset_id: Id,
    pub basis: CorrelationBasis,
    pub confidence: CorrelationConfidence,
    pub status: CorrelationStatus,
    pub rationale: String,
    pub observation_ids: Vec<Id>,
    pub evidence_ids: Vec<Id>,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
    /// Append-only review history, oldest first (the proposal is the first entry).
    pub reviews: Vec<CorrelationReview>,
}

/// An analyst's proposal.
#[derive(Debug, Clone, Deserialize)]
pub struct Proposal {
    pub left_asset_id: Id,
    pub right_asset_id: Id,
    pub basis: CorrelationBasis,
    pub confidence: CorrelationConfidence,
    pub rationale: String,
    pub observation_ids: Vec<Id>,
}

pub const MAX_CITED_OBSERVATIONS: usize = 20;
pub const MAX_TEXT_BYTES: usize = 1024;
pub const MAX_CORRELATIONS: i64 = 500;
const ACTOR: &str = "Analyst";

fn clean_text(value: &str, field: &str) -> Result<String> {
    let cleaned: String = value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_owned();
    if cleaned.is_empty() || cleaned.len() > MAX_TEXT_BYTES {
        return Err(CoreError::new(
            "InvalidRequest",
            &format!("The {field} must be 1–{MAX_TEXT_BYTES} bytes."),
        ));
    }
    Ok(cleaned)
}

fn status_name(status: CorrelationStatus) -> String {
    crate::database::encoded(&status)
}

fn ids(text: &str) -> Vec<Id> {
    serde_json::from_str(text).unwrap_or_default()
}

fn load(
    conn: &rusqlite::Connection,
    workspace: Id,
    filter: Option<Id>,
) -> Result<Vec<Correlation>> {
    let mut statement = conn.prepare(
        "SELECT id,left_asset_id,right_asset_id,basis,confidence,status,rationale,observation_ids,evidence_ids,created_by,created_at,updated_at
         FROM correlations WHERE workspace_id=?1 AND (?2 IS NULL OR id=?2) ORDER BY created_at,id",
    )?;
    let parse = |s: String| -> rusqlite::Result<Id> {
        Id::parse_str(&s).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })
    };
    let enum_of = |s: String| serde_json::Value::String(s);
    let rows = statement.query_map(
        params![workspace.to_string(), filter.map(|f| f.to_string())],
        |row| {
            Ok(Correlation {
                id: parse(row.get(0)?)?,
                workspace_id: workspace,
                left_asset_id: parse(row.get(1)?)?,
                right_asset_id: parse(row.get(2)?)?,
                basis: serde_json::from_value(enum_of(row.get(3)?))
                    .unwrap_or(CorrelationBasis::AnalystReview),
                confidence: serde_json::from_value(enum_of(row.get(4)?))
                    .unwrap_or(CorrelationConfidence::Low),
                status: serde_json::from_value(enum_of(row.get(5)?))
                    .unwrap_or(CorrelationStatus::Proposed),
                rationale: row.get(6)?,
                observation_ids: ids(&row.get::<_, String>(7)?),
                evidence_ids: ids(&row.get::<_, String>(8)?),
                created_by: row.get(9)?,
                created_at: row.get(10)?,
                updated_at: row.get(11)?,
                reviews: Vec::new(),
            })
        },
    )?;
    let mut correlations = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    let mut reviews = conn.prepare(
        "SELECT id,from_status,to_status,note,actor,timestamp FROM correlation_reviews
         WHERE workspace_id=?1 AND correlation_id=?2 ORDER BY timestamp,rowid",
    )?;
    for correlation in &mut correlations {
        correlation.reviews = reviews
            .query_map(
                params![workspace.to_string(), correlation.id.to_string()],
                |row| {
                    let from: Option<String> = row.get(1)?;
                    Ok(CorrelationReview {
                        id: parse(row.get(0)?)?,
                        from_status: from.and_then(|f| serde_json::from_value(enum_of(f)).ok()),
                        to_status: serde_json::from_value(enum_of(row.get(2)?))
                            .unwrap_or(CorrelationStatus::Proposed),
                        note: row.get(3)?,
                        actor: row.get(4)?,
                        timestamp: row.get(5)?,
                    })
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
    }
    Ok(correlations)
}

/// Every correlation in a workspace (with review history), oldest first.
pub fn correlations_in(conn: &rusqlite::Connection, workspace: Id) -> Result<Vec<Correlation>> {
    load(conn, workspace, None)
}

impl Store {
    /// Record an analyst's correlation proposal after validating that it is
    /// evidence-backed for both assets. Never modifies any asset.
    pub fn propose_correlation(&self, workspace: Id, proposal: Proposal) -> Result<Correlation> {
        let rationale = clean_text(&proposal.rationale, "rationale")?;
        if proposal.left_asset_id == proposal.right_asset_id {
            return Err(CoreError::new(
                "InvalidRequest",
                "A correlation links two different assets; identical assets are already one canonical asset.",
            ));
        }
        if proposal.basis == CorrelationBasis::SharedIdentifier
            && proposal.confidence != CorrelationConfidence::Low
        {
            return Err(CoreError::new(
                "InvalidRequest",
                "A shared identifier is a weak signal: its confidence is capped at LOW.",
            ));
        }
        let mut cited = proposal.observation_ids.clone();
        cited.sort();
        cited.dedup();
        if cited.is_empty() || cited.len() > MAX_CITED_OBSERVATIONS {
            return Err(CoreError::new(
                "InvalidRequest",
                &format!("Cite 1–{MAX_CITED_OBSERVATIONS} observations as evidence."),
            ));
        }
        let (left, right) =
            if proposal.left_asset_id.to_string() < proposal.right_asset_id.to_string() {
                (proposal.left_asset_id, proposal.right_asset_id)
            } else {
                (proposal.right_asset_id, proposal.left_asset_id)
            };
        let mut conn = self.connect(workspace)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for asset in [left, right] {
            let exists: bool = tx
                .prepare("SELECT 1 FROM assets WHERE workspace_id=?1 AND id=?2")?
                .exists(params![workspace.to_string(), asset.to_string()])?;
            if !exists {
                return Err(CoreError::new(
                    "AssetNotFound",
                    "Both assets must exist in this workspace.",
                ));
            }
        }
        let mut evidence: Vec<Id> = Vec::new();
        let (mut cites_left, mut cites_right) = (false, false);
        for observation in &cited {
            let row: Option<(String, Option<String>)> = tx
                .query_row(
                    "SELECT asset_id,evidence_id FROM observations WHERE workspace_id=?1 AND id=?2",
                    params![workspace.to_string(), observation.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((asset, evidence_id)) = row else {
                return Err(CoreError::new(
                    "InvalidRequest",
                    "A cited observation does not exist in this workspace.",
                ));
            };
            let Some(evidence_id) = evidence_id.and_then(|e| Id::parse_str(&e).ok()) else {
                return Err(CoreError::new(
                    "InvalidRequest",
                    "Every cited observation must be backed by evidence (analyst-entered targets are not).",
                ));
            };
            if asset == left.to_string() {
                cites_left = true;
            } else if asset == right.to_string() {
                cites_right = true;
            } else {
                return Err(CoreError::new(
                    "InvalidRequest",
                    "A cited observation belongs to neither asset.",
                ));
            }
            if !evidence.contains(&evidence_id) {
                evidence.push(evidence_id);
            }
        }
        if !(cites_left && cites_right) {
            return Err(CoreError::new(
                "InvalidRequest",
                "Cite at least one evidence-backed observation for each asset.",
            ));
        }
        let existing: Option<String> = tx
            .query_row(
                "SELECT status FROM correlations WHERE workspace_id=?1 AND left_asset_id=?2 AND right_asset_id=?3",
                params![workspace.to_string(), left.to_string(), right.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(CoreError::new(
                "CorrelationExists",
                "These assets already have a correlation; review it (reopen, confirm, reject, or retract) instead.",
            ));
        }
        let count: i64 = tx.query_row("SELECT COUNT(*) FROM correlations", [], |r| r.get(0))?;
        if count >= MAX_CORRELATIONS {
            return Err(CoreError::new(
                "BudgetExceeded",
                "The correlation limit is 500 per workspace.",
            ));
        }
        let id = Id::new_v4();
        let now = crate::now();
        tx.execute(
            "INSERT INTO correlations VALUES(?1,?2,?3,?4,?5,?6,'PROPOSED',?7,?8,?9,?10,?11,?11)",
            params![
                id.to_string(),
                workspace.to_string(),
                left.to_string(),
                right.to_string(),
                crate::database::encoded(&proposal.basis),
                crate::database::encoded(&proposal.confidence),
                rationale,
                serde_json::to_string(&cited)?,
                serde_json::to_string(&evidence)?,
                ACTOR,
                now
            ],
        )?;
        tx.execute(
            "INSERT INTO correlation_reviews VALUES(?1,?2,?3,NULL,'PROPOSED',?4,?5,?6)",
            params![
                Id::new_v4().to_string(),
                workspace.to_string(),
                id.to_string(),
                "Proposed",
                ACTOR,
                now
            ],
        )?;
        emit(
            &tx,
            workspace,
            EventType::CorrelationProposed,
            json!({"correlation_id": id, "left_asset_id": left, "right_asset_id": right,
                   "basis": proposal.basis, "confidence": proposal.confidence}),
        )?;
        audit(&tx, workspace, "CorrelationProposed", id)?;
        let correlation = load(&tx, workspace, Some(id))?
            .pop()
            .ok_or_else(|| CoreError::new("DatabaseError", "Correlation was not stored."))?;
        tx.commit()?;
        Ok(correlation)
    }

    /// Apply an explicit review decision. Only the documented transitions are
    /// allowed; every decision is appended to the review log with its note.
    pub fn review_correlation(
        &self,
        workspace: Id,
        correlation: Id,
        decision: ReviewDecision,
        note: &str,
    ) -> Result<Correlation> {
        let note = clean_text(note, "review note")?;
        let mut conn = self.connect(workspace)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load(&tx, workspace, Some(correlation))?
            .pop()
            .ok_or_else(|| {
                CoreError::new(
                    "CorrelationNotFound",
                    "Correlation does not exist in this workspace.",
                )
            })?;
        let next = decision.apply(current.status).ok_or_else(|| {
            CoreError::new(
                "InvalidTransition",
                "That review decision does not apply to the correlation's current status.",
            )
        })?;
        let now = crate::now();
        tx.execute(
            "UPDATE correlations SET status=?1,updated_at=?2 WHERE workspace_id=?3 AND id=?4",
            params![
                status_name(next),
                now,
                workspace.to_string(),
                correlation.to_string()
            ],
        )?;
        tx.execute(
            "INSERT INTO correlation_reviews VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                Id::new_v4().to_string(),
                workspace.to_string(),
                correlation.to_string(),
                status_name(current.status),
                status_name(next),
                note,
                ACTOR,
                now
            ],
        )?;
        emit(
            &tx,
            workspace,
            EventType::CorrelationReviewed,
            json!({"correlation_id": correlation, "from": current.status, "to": next, "decision": decision}),
        )?;
        audit(&tx, workspace, "CorrelationReviewed", correlation)?;
        let updated = load(&tx, workspace, Some(correlation))?
            .pop()
            .ok_or_else(|| CoreError::new("DatabaseError", "Correlation was not stored."))?;
        tx.commit()?;
        Ok(updated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_documented_transitions_apply() {
        use CorrelationStatus::*;
        assert_eq!(ReviewDecision::Confirm.apply(Proposed), Some(Confirmed));
        assert_eq!(ReviewDecision::Reject.apply(Proposed), Some(Rejected));
        assert_eq!(ReviewDecision::Retract.apply(Confirmed), Some(Retracted));
        assert_eq!(ReviewDecision::Reopen.apply(Rejected), Some(Proposed));
        assert_eq!(ReviewDecision::Reopen.apply(Retracted), Some(Proposed));
        for (decision, from) in [
            (ReviewDecision::Confirm, Confirmed),
            (ReviewDecision::Confirm, Rejected),
            (ReviewDecision::Retract, Proposed),
            (ReviewDecision::Reject, Confirmed),
            (ReviewDecision::Reopen, Proposed),
        ] {
            assert_eq!(decision.apply(from), None);
        }
    }

    #[test]
    fn text_is_bounded_and_control_free() {
        assert_eq!(
            clean_text("  same\u{0}handle  ", "x").unwrap(),
            "same handle"
        );
        assert!(clean_text("   ", "x").is_err());
        assert!(clean_text(&"a".repeat(MAX_TEXT_BYTES + 1), "x").is_err());
    }
}
