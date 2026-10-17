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
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
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
    /// Bounded normalized per-run facts (display consumers still redact sensitive URLs).
    pub metadata: Value,
    /// Explicitly distinguishes oversized supplemental facts from historical absence.
    pub metadata_omitted: bool,
}

/// A chain's normalized results.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResultProjection {
    pub workspace_id: Id,
    pub chain_id: Id,
    pub chain_name: String,
    pub items: Vec<ResultItem>,
}

/// Cap a per-observation metadata blob so a projection can never carry an unbounded
/// object (observations are already bounded upstream; this is defense in depth).
const MAX_METADATA_BYTES: usize = 32 * 1024;
const MAX_ITEMS: usize = 10_000;
const MAX_PROJECTION_BYTES: usize = 6 * 1024 * 1024;
fn too_large() -> CoreError {
    CoreError::new("ResultsTooLarge", "The normalized result projection exceeds its review limit. Review Assets and Evidence separately.")
}

impl Store {
    /// Project one chain's durable observations into typed, provenance-carrying result
    /// items. Read-only; reconstructs from committed state (survives restart).
    pub fn result_projection(&self, workspace: Id, chain: Id) -> Result<ResultProjection> {
        let directory = self.directory(workspace);
        let path = directory.join("workspace.sqlite");
        if !path.is_file() {
            return Err(CoreError::new(
                "WorkspaceNotFound",
                "Workspace does not exist.",
            ));
        }
        if directory.is_symlink() || path.is_symlink() {
            return Err(CoreError::new(
                "StorageError",
                "Workspace paths cannot be symbolic links.",
            ));
        }
        let mut connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        let conn = connection.transaction()?;
        // Migrations belong to normal core/workspace opening, never this read model.
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if !(4..=8).contains(&version) {
            return Err(CoreError::new(
                "MigrationFailure",
                "Open this workspace with a compatible core before projecting results.",
            ));
        }
        let workspace_exists: bool = conn
            .prepare("SELECT 1 FROM workspaces WHERE id=?1")?
            .exists([workspace.to_string()])?;
        if !workspace_exists {
            return Err(CoreError::new(
                "WorkspaceNotFound",
                "Workspace identity does not match its store.",
            ));
        }
        let chain_name: Option<String> = conn
            .query_row(
                "SELECT name FROM chain_runs WHERE workspace_id=?1 AND id=?2",
                params![workspace.to_string(), chain.to_string()],
                |r| r.get(0),
            )
            .optional()?;
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
                    a.asset_type,a.canonical_identity,r.provider_id,
                    EXISTS(SELECT 1 FROM relationship_observations ro
                      JOIN asset_relationships rel ON rel.workspace_id=ro.workspace_id AND rel.id=ro.relationship_id
                      WHERE ro.workspace_id=o.workspace_id AND ro.provider_run_id=o.provider_run_id
                        AND ro.evidence_id=o.evidence_id AND rel.source_asset_id=o.source_asset_id
                        AND rel.destination_asset_id=o.asset_id)
             FROM observations o
             JOIN assets a ON a.workspace_id=o.workspace_id AND a.id=o.asset_id
             LEFT JOIN provider_runs r ON r.workspace_id=o.workspace_id AND r.id=o.provider_run_id
             WHERE o.workspace_id=?1 AND o.provider_run_id IN (
                 SELECT id FROM provider_runs WHERE workspace_id=?1 AND chain_id=?2)
             ORDER BY o.timestamp,o.id LIMIT 10001",
        )?;
        let rows =
            statement.query_map(params![workspace.to_string(), chain.to_string()], |row| {
                let source_asset_id = row.get::<_, Option<String>>(2)?.map(parse).transpose()?;
                let metadata: Option<String> = row.get(9)?;
                let metadata_omitted = metadata
                    .as_ref()
                    .is_some_and(|m| m.len() > MAX_METADATA_BYTES);
                let metadata = if metadata_omitted {
                    Value::Null
                } else {
                    metadata
                        .map(|m| {
                            serde_json::from_str::<Value>(&m).map_err(|e| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    9,
                                    rusqlite::types::Type::Text,
                                    Box::new(e),
                                )
                            })
                        })
                        .transpose()?
                        .unwrap_or(Value::Null)
                };
                Ok(ResultItem {
                    kind: if row.get::<_, bool>(13)? {
                        ResultItemKind::RelationshipObservation
                    } else {
                        ResultItemKind::AssetObservation
                    },
                    observation_id: parse(row.get(0)?)?,
                    asset_id: parse(row.get(1)?)?,
                    source_asset_id,
                    run_id: row.get::<_, Option<String>>(3)?.map(parse).transpose()?,
                    evidence_id: row.get::<_, Option<String>>(4)?.map(parse).transpose()?,
                    discovered_by: row.get(5)?,
                    observed_value: row.get(6)?,
                    timestamp: row.get(7)?,
                    confidence: row.get(8)?,
                    metadata,
                    metadata_omitted,
                    asset_type: row.get(10)?,
                    asset_identity: row.get(11)?,
                    provider_id: row.get(12)?,
                })
            })?;
        let mut items = Vec::new();
        let mut bytes = chain_name.len();
        for row in rows {
            let item = row?;
            bytes += serde_json::to_vec(&item)?.len();
            if items.len() == MAX_ITEMS || bytes > MAX_PROJECTION_BYTES {
                return Err(too_large());
            }
            items.push(item);
        }
        let projection = ResultProjection {
            workspace_id: workspace,
            chain_id: chain,
            chain_name,
            items,
        };
        if serde_json::to_vec(&projection)?.len() > MAX_PROJECTION_BYTES {
            return Err(too_large());
        }
        drop(statement);
        conn.commit()?;
        Ok(projection)
    }
}
