//! Normalized result projection (Issue #76).
//!
//! The durable workspace graph (Asset / Observation / Relationship / Evidence / runs) is
//! the single source of truth. A `ResultProjection` is a **read model** derived from
//! those records for one chain run — a typed, provenance-carrying view that consumers
//! (Recon/OSINT results, the Create-Finding action, future reports/exports/AI) read
//! instead of parsing a provider's raw stdout. It stores nothing new; it never contains
//! console text or an opaque blob as its only contract. Per-provider supplemental facts
//! ride along as a bounded `metadata` object, but the semantic core — which entity was
//! observed, which run and provider produced it, which evidence supports it, and when —
//! is typed.

use crate::{
    assets::Id,
    database::Store,
    error::{CoreError, Result},
};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// What a result item is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResultItemKind {
    /// A canonical asset a provider observed.
    AssetObservation,
    /// An observation that also links a source asset to the observed asset (e.g.
    /// `resolves_to`, `has_account`): the source is carried for context.
    RelationshipObservation,
}

/// One normalized, provenance-carrying result row derived from a durable observation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResultItem {
    pub kind: ResultItemKind,
    pub observation_id: Id,
    /// The canonical entity observed.
    pub asset_id: Id,
    pub asset_type: String,
    pub asset_identity: String,
    /// For a relationship observation, the source asset it was linked from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_asset_id: Option<Id>,
    /// Provenance: the run and provider that produced it, and the supporting evidence.
    pub run_id: Option<Id>,
    pub provider_id: Option<String>,
    pub discovered_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_id: Option<Id>,
    pub observed_value: String,
    pub confidence: String,
    pub timestamp: String,
    /// Bounded, already-sanitized per-run facts (never raw stdout).
    pub metadata: Value,
}

/// A chain's normalized results.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResultProjection {
    pub chain_id: Id,
    pub chain_name: String,
    pub items: Vec<ResultItem>,
}

/// Cap a per-observation metadata blob so a projection can never carry an unbounded
/// object (observations are already bounded upstream; this is defense in depth).
const MAX_METADATA_BYTES: usize = 32 * 1024;

impl Store {
    /// Project one chain's durable observations into typed, provenance-carrying result
    /// items. Read-only; reconstructs from committed state (survives restart).
    pub fn result_projection(&self, workspace: Id, chain: Id) -> Result<ResultProjection> {
        let conn = self.connect(workspace)?;
        let chain_name: Option<String> = conn
            .query_row(
                "SELECT name FROM chain_runs WHERE workspace_id=?1 AND id=?2",
                params![workspace.to_string(), chain.to_string()],
                |r| r.get(0),
            )
            .ok();
        let Some(chain_name) = chain_name else {
            return Err(CoreError::new(
                "InvalidRequest",
                "That chain does not exist in this workspace.",
            ));
        };

        let parse = |s: String| -> rusqlite::Result<Id> {
            Id::parse_str(&s).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })
        };
        let mut statement = conn.prepare(
            "SELECT o.id,o.asset_id,o.source_asset_id,o.provider_run_id,o.evidence_id,
                    o.discovered_by,o.observed_value,o.timestamp,o.confidence,o.metadata,
                    a.asset_type,a.canonical_identity,r.provider_id
             FROM observations o
             JOIN assets a ON a.workspace_id=o.workspace_id AND a.id=o.asset_id
             LEFT JOIN provider_runs r ON r.workspace_id=o.workspace_id AND r.id=o.provider_run_id
             WHERE o.workspace_id=?1 AND o.provider_run_id IN (
                 SELECT id FROM provider_runs WHERE workspace_id=?1 AND chain_id=?2)
             ORDER BY o.timestamp,o.id",
        )?;
        let rows =
            statement.query_map(params![workspace.to_string(), chain.to_string()], |row| {
                let source_asset_id = row
                    .get::<_, Option<String>>(2)?
                    .and_then(|s| Id::parse_str(&s).ok());
                let metadata: Option<String> = row.get(9)?;
                let metadata = metadata
                    .filter(|m| m.len() <= MAX_METADATA_BYTES)
                    .and_then(|m| serde_json::from_str::<Value>(&m).ok())
                    .unwrap_or(Value::Null);
                Ok(ResultItem {
                    kind: if source_asset_id.is_some() {
                        ResultItemKind::RelationshipObservation
                    } else {
                        ResultItemKind::AssetObservation
                    },
                    observation_id: parse(row.get(0)?)?,
                    asset_id: parse(row.get(1)?)?,
                    source_asset_id,
                    run_id: row
                        .get::<_, Option<String>>(3)?
                        .and_then(|s| Id::parse_str(&s).ok()),
                    evidence_id: row
                        .get::<_, Option<String>>(4)?
                        .and_then(|s| Id::parse_str(&s).ok()),
                    discovered_by: row.get(5)?,
                    observed_value: row.get(6)?,
                    timestamp: row.get(7)?,
                    confidence: row.get(8)?,
                    metadata,
                    asset_type: row.get(10)?,
                    asset_identity: row.get(11)?,
                    provider_id: row.get(12)?,
                })
            })?;
        let items = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| CoreError::new("DatabaseError", "Could not project chain results."))?;
        Ok(ResultProjection {
            chain_id: chain,
            chain_name,
            items,
        })
    }
}
