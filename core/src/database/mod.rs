use crate::{
    assets::*,
    error::{CoreError, Result},
    events::{Event, EventType},
    targets::{self, Target, TargetType},
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone)]
pub struct Store {
    pub root: PathBuf,
}

/// Read-only scope coverage for a target, computed with the core's own scope logic so
/// the UI never reimplements wildcard/CIDR/URL-host matching. Performs no network I/O.
#[derive(Debug, Serialize)]
pub struct ScopeStatus {
    pub authorized: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_scope_entry: Option<String>,
}

/// Result of authorizing a target from the Recon flow: the updated workspace and the
/// exact entry that was added (`None` when the target was already covered).
#[derive(Debug, Serialize)]
pub struct AuthorizeResult {
    pub workspace: Workspace,
    pub authorized: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub added_entry: Option<String>,
}

pub fn encoded<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .expect("serializable domain value")
        .as_str()
        .expect("enum string")
        .to_owned()
}

pub fn rows<T: DeserializeOwned>(
    conn: &Connection,
    sql: &str,
    parameters: impl rusqlite::Params,
) -> Result<Vec<T>> {
    let mut statement = conn.prepare(sql)?;
    let values = statement.query_map(parameters, |row| row.get::<_, String>(0))?;
    values.map(|row| Ok(serde_json::from_str(&row?)?)).collect()
}

pub fn migrate(conn: &mut Connection) -> Result<()> {
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.pragma_update(None, "foreign_keys", true)?;
    const LATEST: i64 = 5;
    let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version > LATEST {
        return Err(CoreError::new(
            "MigrationFailure",
            "This workspace requires a newer MACSPLOIT core.",
        ));
    }
    if version < 1 {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(include_str!("../../migrations/001_initial.sql"))
            .map_err(|_| {
                CoreError::new("MigrationFailure", "Initial workspace migration failed.")
            })?;
        tx.pragma_update(None, "user_version", 1)?;
        tx.commit()?;
    }
    if version < 2 {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(include_str!("../../migrations/002_domain_recon.sql"))
            .map_err(|_| CoreError::new("MigrationFailure", "Domain-recon migration failed."))?;
        tx.pragma_update(None, "user_version", 2)?;
        tx.commit()?;
    }
    if version < 3 {
        rebuild_migration(
            conn,
            include_str!("../../migrations/003_reverse_dns.sql"),
            3,
            "Reverse-DNS",
        )?;
    }
    if version < 4 {
        rebuild_migration(
            conn,
            include_str!("../../migrations/004_osint.sql"),
            4,
            "OSINT",
        )?;
    }
    if version < 5 {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(include_str!("../../migrations/005_chain_error_message.sql"))
            .map_err(|_| CoreError::new("MigrationFailure", "Chain-error-detail migration failed."))?;
        tx.pragma_update(None, "user_version", 5)?;
        tx.commit()?;
    }
    Ok(())
}

/// Run a migration that rebuilds a table (CHECK change). Rebuilding asset_relationships
/// requires foreign keys off so the relationship_observations FK survives the
/// drop/rename. Pragma can't change inside a transaction, so toggle it around a
/// dedicated migration transaction and verify referential integrity before commit.
fn rebuild_migration(conn: &mut Connection, sql: &str, version: i64, label: &str) -> Result<()> {
    conn.pragma_update(None, "foreign_keys", false)?;
    let result = (|| -> Result<()> {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(sql).map_err(|_| {
            CoreError::new("MigrationFailure", &format!("{label} migration failed."))
        })?;
        let invalid: bool = tx.prepare("PRAGMA foreign_key_check")?.exists([])?;
        if invalid {
            return Err(CoreError::new(
                "MigrationFailure",
                &format!("{label} migration violates referential integrity."),
            ));
        }
        tx.pragma_update(None, "user_version", version)?;
        tx.commit()?;
        Ok(())
    })();
    conn.pragma_update(None, "foreign_keys", true)?;
    result
}

pub fn emit(conn: &Connection, workspace: Id, kind: EventType, payload: Value) -> Result<()> {
    conn.execute(
        "INSERT INTO events(id,workspace_id,timestamp,event_type,payload) VALUES(?1,?2,?3,?4,?5)",
        params![
            Id::new_v4().to_string(),
            workspace.to_string(),
            crate::now(),
            encoded(&kind),
            payload.to_string()
        ],
    )?;
    conn.execute(
        "UPDATE workspaces SET updated_at=?1 WHERE id=?2",
        params![crate::now(), workspace.to_string()],
    )?;
    Ok(())
}

pub fn audit(conn: &Connection, workspace: Id, action: &str, subject: Id) -> Result<()> {
    conn.execute(
        "INSERT INTO audit_events VALUES(?1,?2,?3,?4,?5)",
        params![
            Id::new_v4().to_string(),
            workspace.to_string(),
            crate::now(),
            action,
            subject.to_string()
        ],
    )?;
    Ok(())
}

pub fn private_directory(path: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(CoreError::new(
            "StorageError",
            "Application data directories cannot be symbolic links.",
        ));
    }
    Ok(())
}

impl Store {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        if !root.is_absolute() {
            return Err(CoreError::new(
                "StorageError",
                "Application storage must use an absolute path.",
            ));
        }
        private_directory(root)?;
        let root = root.canonicalize()?;
        if root.ancestors().any(|path| path.join(".git").exists()) {
            return Err(CoreError::new(
                "StorageError",
                "Runtime workspaces must not be stored in a Git repository.",
            ));
        }
        private_directory(&root.join("workspaces"))?;
        Ok(Self { root })
    }

    pub fn directory(&self, id: Id) -> PathBuf {
        self.root.join("workspaces").join(id.to_string())
    }

    pub fn connect(&self, id: Id) -> Result<Connection> {
        let directory = self.directory(id);
        let path = directory.join("workspace.sqlite");
        if !path.is_file() {
            return Err(CoreError::new(
                "WorkspaceNotFound",
                "Workspace does not exist.",
            ));
        }
        if fs::symlink_metadata(&directory)?.file_type().is_symlink()
            || fs::symlink_metadata(&path)?.file_type().is_symlink()
        {
            return Err(CoreError::new(
                "StorageError",
                "Workspace paths cannot be symbolic links.",
            ));
        }
        let mut conn = Connection::open(path)?;
        migrate(&mut conn)?;
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM workspaces WHERE id=?1)",
            [id.to_string()],
            |r| r.get(0),
        )?;
        if !exists {
            return Err(CoreError::new(
                "WorkspaceNotFound",
                "Workspace identity does not match its store.",
            ));
        }
        Ok(conn)
    }

    pub fn create_workspace(&self, name: &str, scope: &[String]) -> Result<Workspace> {
        let name = name.trim();
        if name.is_empty()
            || name.len() > 120
            || name.chars().any(char::is_control)
            || scope.len() > 100
        {
            return Err(CoreError::new(
                "InvalidWorkspace",
                "Use a workspace name of 1–120 bytes and at most 100 scope entries.",
            ));
        }
        let mut scope: Vec<_> = scope
            .iter()
            .map(|s| crate::scope::normalize_entry(s.trim()))
            .collect::<Result<_>>()?;
        scope.sort();
        scope.dedup();
        let id = Id::new_v4();
        let directory = self.directory(id);
        private_directory(&directory.join("evidence"))?;
        let mut conn = Connection::open(directory.join("workspace.sqlite"))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        migrate(&mut conn)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let timestamp = crate::now();
        tx.execute(
            "INSERT INTO workspaces VALUES(?1,?2,?3,?3)",
            params![id.to_string(), name, timestamp],
        )?;
        for entry in &scope {
            tx.execute(
                "INSERT INTO scope_entries VALUES(?1,?2)",
                params![id.to_string(), entry],
            )?;
        }
        emit(
            &tx,
            id,
            EventType::WorkspaceCreated,
            json!({"workspace_id":id,"name":name}),
        )?;
        audit(&tx, id, "WorkspaceCreated", id)?;
        tx.commit()?;
        self.workspace(id)
    }

    pub fn update_workspace_scope(&self, id: Id, scope: &[String]) -> Result<Workspace> {
        if scope.len() > 100 {
            return Err(CoreError::new(
                "InvalidWorkspace",
                "A workspace can have at most 100 scope entries.",
            ));
        }
        let mut normalized: Vec<_> = scope
            .iter()
            .map(|entry| crate::scope::normalize_entry(entry.trim()))
            .collect::<Result<_>>()?;
        normalized.sort();
        normalized.dedup();

        let mut conn = self.connect(id)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM scope_entries WHERE workspace_id=?1",
            [id.to_string()],
        )?;
        for entry in &normalized {
            tx.execute(
                "INSERT INTO scope_entries VALUES(?1,?2)",
                params![id.to_string(), entry],
            )?;
        }
        let timestamp = crate::now();
        tx.execute(
            "UPDATE workspaces SET updated_at=?1 WHERE id=?2",
            params![timestamp, id.to_string()],
        )?;
        emit(
            &tx,
            id,
            EventType::WorkspaceScopeUpdated,
            json!({"workspace_id":id,"scope_count":normalized.len()}),
        )?;
        audit(&tx, id, "WorkspaceScopeUpdated", id)?;
        tx.commit()?;
        self.workspace(id)
    }

    pub fn workspace(&self, id: Id) -> Result<Workspace> {
        workspace(&self.connect(id)?, id)
    }

    /// Whether the selected target is currently covered by workspace scope, plus the
    /// narrowest exact entry that would authorize it. Read-only: no scope mutation and
    /// no network activity. Scope coverage reuses `scope::contains` (the authoritative
    /// matcher), so Swift does not define a second notion of coverage.
    pub fn target_scope_status(&self, workspace_id: Id, target_id: Id) -> Result<ScopeStatus> {
        let conn = self.connect(workspace_id)?;
        let ws = workspace(&conn, workspace_id)?;
        let target = targets_in(&conn, workspace_id)?
            .into_iter()
            .find(|t| t.id == target_id)
            .ok_or_else(|| {
                CoreError::new("InvalidTarget", "Target does not exist in this workspace.")
            })?;
        Ok(ScopeStatus {
            authorized: crate::scope::contains(&ws.scope, &target.normalized_value),
            required_scope_entry: crate::scope::target_entry(
                target.target_type,
                &target.normalized_value,
            ),
        })
    }

    /// Add only the narrowest exact scope entry required to authorize the target, if it
    /// is not already covered, then re-check core authorization. A no-op (no write, no
    /// event) when the target is already in scope. Never widens to wildcards, CIDRs,
    /// sibling hosts, or resolved IPs, and performs no network activity. The durable
    /// `WorkspaceScopeUpdated` event records the added entry and that it came from the
    /// Recon authorization flow (operator intent — not proof of permission).
    pub fn authorize_target(&self, workspace_id: Id, target_id: Id) -> Result<AuthorizeResult> {
        let mut conn = self.connect(workspace_id)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let ws = workspace(&tx, workspace_id)?;
        let target = targets_in(&tx, workspace_id)?
            .into_iter()
            .find(|t| t.id == target_id)
            .ok_or_else(|| {
                CoreError::new("InvalidTarget", "Target does not exist in this workspace.")
            })?;

        // Already covered: do not touch scope or emit an event.
        if crate::scope::contains(&ws.scope, &target.normalized_value) {
            return Ok(AuthorizeResult {
                workspace: ws,
                authorized: true,
                added_entry: None,
            });
        }

        let entry = crate::scope::target_entry(target.target_type, &target.normalized_value)
            .ok_or_else(|| {
                CoreError::new(
                    "InvalidTarget",
                    "This target type cannot be authorized from Recon.",
                )
            })?;
        if ws.scope.len() >= 100 {
            return Err(CoreError::new(
                "InvalidWorkspace",
                "A workspace can have at most 100 scope entries.",
            ));
        }
        tx.execute(
            "INSERT OR IGNORE INTO scope_entries VALUES(?1,?2)",
            params![workspace_id.to_string(), entry],
        )?;
        tx.execute(
            "UPDATE workspaces SET updated_at=?1 WHERE id=?2",
            params![crate::now(), workspace_id.to_string()],
        )?;
        emit(
            &tx,
            workspace_id,
            EventType::WorkspaceScopeUpdated,
            json!({
                "workspace_id": workspace_id,
                "added": entry,
                "source": "recon_authorization",
                "scope_count": ws.scope.len() + 1,
            }),
        )?;
        audit(&tx, workspace_id, "WorkspaceScopeUpdated", workspace_id)?;
        tx.commit()?;

        // Re-check authorization against the persisted scope (fail closed).
        let updated = self.workspace(workspace_id)?;
        if !crate::scope::contains(&updated.scope, &target.normalized_value) {
            return Err(CoreError::new(
                "ScopeViolation",
                "Authorization did not bring the target into scope.",
            ));
        }
        Ok(AuthorizeResult {
            workspace: updated,
            authorized: true,
            added_entry: Some(entry),
        })
    }

    pub fn list_workspaces(&self) -> Result<Vec<Workspace>> {
        let mut workspaces = Vec::new();
        for entry in fs::read_dir(self.root.join("workspaces"))? {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(id) = name.parse::<Id>() else {
                continue;
            };
            if entry.file_type()?.is_dir() && entry.path().join("workspace.sqlite").exists() {
                workspaces.push(self.workspace(id)?);
            }
        }
        workspaces.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        Ok(workspaces)
    }

    pub fn add_target(&self, workspace_id: Id, input: &str) -> Result<Target> {
        let (kind, normalized) = targets::classify(input)?;
        let mut conn = self.connect(workspace_id)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = targets_in(&tx, workspace_id)?
            .into_iter()
            .find(|target| target.target_type == kind && target.normalized_value == normalized);
        if let Some(existing) = existing {
            return Ok(existing);
        }
        let count: i64 = tx.query_row("SELECT COUNT(*) FROM targets", [], |r| r.get(0))?;
        if count >= 100 {
            return Err(CoreError::new(
                "BudgetExceeded",
                "The Phase 0 workspace target limit is 100.",
            ));
        }
        let asset_kind = match kind {
            TargetType::Domain => Some(AssetType::Domain),
            TargetType::Hostname => Some(AssetType::Hostname),
            TargetType::IPAddress => Some(AssetType::IPAddress),
            TargetType::URL => Some(AssetType::URL),
            _ => None,
        };
        let asset_id = if let Some(kind) = asset_kind {
            let asset = upsert_asset(
                &tx,
                workspace_id,
                kind,
                &normalized,
                json!({"source":"Analyst"}),
            )?;
            observe(
                &tx,
                &Observation {
                    id: Id::new_v4(),
                    workspace_id,
                    asset_id: asset.id,
                    source_asset_id: None,
                    provider_run_id: None,
                    evidence_id: None,
                    discovered_by: "Analyst".into(),
                    observed_value: input.trim().into(),
                    metadata: json!({}),
                    timestamp: crate::now(),
                    confidence: "CONFIRMED".into(),
                    metadata: None,
                },
            )?;
            Some(asset.id)
        } else {
            None
        };
        let target = Target {
            id: Id::new_v4(),
            workspace_id,
            original_value: input.trim().into(),
            normalized_value: normalized,
            target_type: kind,
            created_at: crate::now(),
            asset_id,
        };
        tx.execute(
            "INSERT INTO targets VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                target.id.to_string(),
                workspace_id.to_string(),
                target.original_value,
                target.normalized_value,
                encoded(&kind),
                target.created_at,
                asset_id.map(|id| id.to_string())
            ],
        )?;
        emit(
            &tx,
            workspace_id,
            EventType::TargetAdded,
            json!({"target_id":target.id,"value":target.normalized_value,"target_type":kind}),
        )?;
        audit(&tx, workspace_id, "TargetAdded", target.id)?;
        tx.commit()?;
        Ok(target)
    }

    pub fn events_after(&self, id: Id, sequence: i64) -> Result<Vec<Event>> {
        if sequence < 0 {
            return Err(CoreError::new(
                "InvalidRequest",
                "Event cursors must be nonnegative.",
            ));
        }
        rows(
            &self.connect(id)?,
            &format!(
                "{EVENT_SELECT} WHERE workspace_id=?1 AND sequence>?2 ORDER BY sequence LIMIT 256"
            ),
            params![id.to_string(), sequence],
        )
    }
}

pub fn workspace(conn: &Connection, id: Id) -> Result<Workspace> {
    rows(conn, "SELECT json_object('id',id,'name',name,'created_at',created_at,'updated_at',updated_at,'scope',json((SELECT json_group_array(value) FROM scope_entries WHERE workspace_id=workspaces.id))) FROM workspaces WHERE id=?1", [id.to_string()])?
        .into_iter().next().ok_or_else(|| CoreError::new("WorkspaceNotFound", "Workspace does not exist."))
}

pub const ASSET_SELECT: &str = "SELECT json_object('id',id,'workspace_id',workspace_id,'asset_type',asset_type,'canonical_identity',canonical_identity,'display_value',display_value,'metadata',json(metadata),'first_seen',first_seen,'last_seen',last_seen) FROM assets";
pub const EVENT_SELECT: &str = "SELECT json_object('id',id,'workspace_id',workspace_id,'sequence',sequence,'timestamp',timestamp,'event_type',event_type,'payload',json(payload)) FROM events";

pub fn assets_in(conn: &Connection, id: Id) -> Result<Vec<Asset>> {
    rows(
        conn,
        &format!("{ASSET_SELECT} WHERE workspace_id=?1 ORDER BY first_seen,id"),
        [id.to_string()],
    )
}
pub fn targets_in(conn: &Connection, id: Id) -> Result<Vec<Target>> {
    rows(conn, "SELECT json_object('id',id,'workspace_id',workspace_id,'original_value',original_value,'normalized_value',normalized_value,'target_type',target_type,'created_at',created_at,'asset_id',asset_id) FROM targets WHERE workspace_id=?1 ORDER BY created_at,id", [id.to_string()])
}

pub fn upsert_asset(
    tx: &Transaction<'_>,
    workspace_id: Id,
    kind: AssetType,
    value: &str,
    metadata: Value,
) -> Result<Asset> {
    let canonical = crate::assets::canonical_identity(kind, value)?;
    let previous: Option<String> = tx.query_row("SELECT id FROM assets WHERE workspace_id=?1 AND asset_type=?2 AND canonical_identity=?3",
        params![workspace_id.to_string(),encoded(&kind),canonical], |r|r.get(0)).optional()?;
    let id = previous
        .as_deref()
        .map(Id::parse_str)
        .transpose()
        .map_err(|_| CoreError::new("DatabaseError", "Invalid stored ID."))?
        .unwrap_or_else(Id::new_v4);
    let timestamp = crate::now();
    let count: i64 = tx.query_row("SELECT COUNT(*) FROM assets", [], |r| r.get(0))?;
    if previous.is_none() && count >= 1000 {
        return Err(CoreError::new(
            "BudgetExceeded",
            "The Phase 0 asset limit is 1000.",
        ));
    }
    tx.execute("INSERT INTO assets VALUES(?1,?2,?3,?4,?4,?5,?6,?6) ON CONFLICT(workspace_id,asset_type,canonical_identity) DO UPDATE SET last_seen=excluded.last_seen",
        params![id.to_string(),workspace_id.to_string(),encoded(&kind),canonical,metadata.to_string(),timestamp])?;
    if previous.is_none() {
        emit(
            tx,
            workspace_id,
            EventType::AssetDiscovered,
            json!({"asset_id":id,"value":canonical,"asset_type":kind}),
        )?;
    }
    rows(tx, &format!("{ASSET_SELECT} WHERE id=?1"), [id.to_string()])?
        .into_iter()
        .next()
        .ok_or_else(|| CoreError::new("DatabaseError", "Asset was not stored."))
}

pub fn observe(tx: &Transaction<'_>, observation: &Observation) -> Result<()> {
    tx.execute(
        "INSERT INTO observations VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        params![
            observation.id.to_string(),
            observation.workspace_id.to_string(),
            observation.asset_id.to_string(),
            observation.source_asset_id.map(|id| id.to_string()),
            observation.provider_run_id.map(|id| id.to_string()),
            observation.evidence_id.map(|id| id.to_string()),
            observation.discovered_by,
            observation.observed_value,
            observation.timestamp,
            observation.confidence,
            observation.metadata.as_ref().map(|m| m.to_string())
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reverse_dns_migration_preserves_existing_relationship_provenance() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../../migrations/001_initial.sql"))
            .unwrap();
        conn.execute_batch(include_str!("../../migrations/002_domain_recon.sql"))
            .unwrap();
        conn.execute_batch("PRAGMA user_version=2;
            INSERT INTO workspaces VALUES('w','fixture','t','t');
            INSERT INTO assets VALUES('a','w','Domain','example.test','example.test','{}','t','t');
            INSERT INTO assets VALUES('b','w','IPAddress','192.0.2.1','192.0.2.1','{}','t','t');
            INSERT INTO targets VALUES('t','w','example.test','example.test','Domain','t','a');
            INSERT INTO chain_runs VALUES('c','w','t','DNS','COMPLETED','t','t',NULL);
            INSERT INTO chain_stages VALUES('s','w','c',0,'DNS','DNS_RESOLUTION','COMPLETED','t','t','native_dns');
            INSERT INTO provider_runs VALUES('p','w','c','s','native_dns','built-in','example.test','t','t','COMPLETED',NULL,0);
            INSERT INTO evidence VALUES('e','w','p','native_dns','example.test','t','hash','application/json','e.json',0);
            INSERT INTO asset_relationships VALUES('r','w','a','b','resolves_to','t');
            INSERT INTO relationship_observations VALUES('o','w','r','p','e','t');").unwrap();
        migrate(&mut conn).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT relationship_type FROM asset_relationships WHERE id='r'",
                [],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            "resolves_to"
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM relationship_observations WHERE relationship_id='r'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        assert!(!conn
            .prepare("PRAGMA foreign_key_check")
            .unwrap()
            .exists([])
            .unwrap());
        assert!(conn
            .execute("DELETE FROM asset_relationships WHERE id='r'", [])
            .is_err());
        conn.execute(
            "INSERT INTO asset_relationships VALUES('ptr','w','b','a','ptr_record','t')",
            [],
        )
        .unwrap();
    }

    #[test]
    fn osint_migration_preserves_relationships_and_observations() {
        let mut conn = Connection::open_in_memory().unwrap();
        for sql in [
            include_str!("../../migrations/001_initial.sql"),
            include_str!("../../migrations/002_domain_recon.sql"),
        ] {
            conn.execute_batch(sql).unwrap();
        }
        conn.pragma_update(None, "foreign_keys", false).unwrap();
        conn.execute_batch(include_str!("../../migrations/003_reverse_dns.sql"))
            .unwrap();
        conn.execute_batch("PRAGMA user_version=3;
            INSERT INTO workspaces VALUES('w','fixture','t','t');
            INSERT INTO assets VALUES('a','w','Domain','example.test','example.test','{}','t','t');
            INSERT INTO assets VALUES('b','w','IPAddress','192.0.2.1','192.0.2.1','{}','t','t');
            INSERT INTO targets VALUES('t','w','example.test','example.test','Domain','t','a');
            INSERT INTO chain_runs VALUES('c','w','t','DNS','COMPLETED','t','t',NULL);
            INSERT INTO chain_stages VALUES('s','w','c',0,'DNS','DNS_RESOLUTION','COMPLETED','t','t','native_dns');
            INSERT INTO provider_runs VALUES('p','w','c','s','native_dns','built-in','example.test','t','t','COMPLETED',NULL,0);
            INSERT INTO evidence VALUES('e','w','p','native_dns','example.test','t','hash','application/json','e.json',0);
            INSERT INTO asset_relationships VALUES('r','w','b','a','ptr_record','t');
            INSERT INTO relationship_observations VALUES('o','w','r','p','e','t');
            INSERT INTO observations VALUES('ob','w','b','a','p','e','native_dns','192.0.2.1','t','CONFIRMED');").unwrap();
        migrate(&mut conn).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT relationship_type FROM asset_relationships WHERE id='r'",
                [],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            "ptr_record"
        );
        // Legacy observations keep a NULL metadata column; new ones accept JSON only.
        assert!(conn
            .query_row(
                "SELECT metadata IS NULL FROM observations WHERE id='ob'",
                [],
                |r| r.get::<_, bool>(0)
            )
            .unwrap());
        assert!(conn
            .execute(
                "INSERT INTO observations VALUES('bad','w','b',NULL,NULL,NULL,'x','v','t','REPORTED','not json')",
                []
            )
            .is_err());
        assert!(!conn
            .prepare("PRAGMA foreign_key_check")
            .unwrap()
            .exists([])
            .unwrap());
        conn.execute(
            "INSERT INTO asset_relationships VALUES('acct','w','a','b','has_account','t')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO asset_relationships VALUES('prof','w','b','a','profile_url','t')",
            [],
        )
        .unwrap();
        assert!(conn
            .execute(
                "INSERT INTO asset_relationships VALUES('nope','w','a','a','owned_by','t')",
                []
            )
            .is_err());
    }

    #[test]
    fn migration_is_versioned_idempotent_and_enforces_foreign_keys() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn).unwrap();
        migrate(&mut conn).unwrap();
        assert_eq!(
            conn.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            5
        );
        // The provider_id column added by migration 002 is present.
        assert!(conn
            .execute(
                "UPDATE chain_stages SET provider_id='synthetic' WHERE 0",
                []
            )
            .is_ok());
        assert!(conn
            .execute(
                "INSERT INTO scope_entries VALUES('absent','example.test')",
                []
            )
            .is_err());
        conn.pragma_update(None, "user_version", 999).unwrap();
        assert_eq!(migrate(&mut conn).unwrap_err().code, "MigrationFailure");
    }
    #[test]
    fn workspace_scope_can_be_replaced_and_persists() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let workspace = store
            .create_workspace("Editable Scope", &["example.test".into()])
            .unwrap();

        let updated = store
            .update_workspace_scope(
                workspace.id,
                &[
                    "EXAMPLE.COM".into(),
                    "*.example.com".into(),
                    "192.0.2.1/24".into(),
                    "example.com".into(),
                ],
            )
            .unwrap();
        assert_eq!(
            updated.scope,
            vec![
                "*.example.com".to_string(),
                "192.0.2.0/24".to_string(),
                "example.com".to_string()
            ]
        );

        let reopened = Store::open(directory.path()).unwrap();
        assert_eq!(
            reopened.workspace(workspace.id).unwrap().scope,
            updated.scope
        );
    }

    #[test]
    fn workspace_and_targets_survive_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let workspace = store
            .create_workspace("Test Assessment", &["example.test".into()])
            .unwrap();
        let target = store.add_target(workspace.id, "EXAMPLE.TEST").unwrap();
        assert_eq!(
            target.id,
            store.add_target(workspace.id, "example.test").unwrap().id
        );
        let reopened = Store::open(directory.path()).unwrap();
        assert_eq!(reopened.list_workspaces().unwrap().len(), 1);
        let conn = reopened.connect(workspace.id).unwrap();
        assert_eq!(assets_in(&conn, workspace.id).unwrap().len(), 1);
        assert_eq!(targets_in(&conn, workspace.id).unwrap()[0].id, target.id);
    }
    #[test]
    fn event_replay_is_ordered_and_strictly_after_cursor() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let workspace = store.create_workspace("Replay", &[]).unwrap();
        let first = store.events_after(workspace.id, 0).unwrap();
        store.add_target(workspace.id, "example.test").unwrap();
        let later = store.events_after(workspace.id, first[0].sequence).unwrap();
        assert_eq!(later.len(), 2);
        assert!(later.windows(2).all(|w| w[0].sequence < w[1].sequence));
        assert!(later.iter().all(|e| e.sequence > first[0].sequence));
    }
    #[test]
    fn invalid_workspace_and_unknown_ids_fail_cleanly() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        assert!(store.create_workspace("", &[]).is_err());
        assert_eq!(
            store.workspace(Id::new_v4()).unwrap_err().code,
            "WorkspaceNotFound"
        );
    }
}
