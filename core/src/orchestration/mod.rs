use crate::{
    assets::*,
    database::{self, *},
    error::{CoreError, Result},
    events::{ChainStatus, Event, EventType, TaskStatus},
    evidence::{Evidence, EVIDENCE_SELECT},
    providers::{Capability, ProviderRegistry},
    targets::{Target, TargetType},
};
use rusqlite::{params, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainRun {
    pub id: Id,
    pub workspace_id: Id,
    pub target_id: Id,
    pub name: String,
    pub status: ChainStatus,
    pub created_at: String,
    pub updated_at: String,
    pub error_code: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage {
    pub id: Id,
    pub workspace_id: Id,
    pub chain_id: Id,
    pub position: u32,
    pub name: String,
    pub capability: Option<Capability>,
    pub status: TaskStatus,
    pub started_at: Option<String>,
    pub ended_at: Option<String>,
    /// When set, the exact provider that must run this stage. Disambiguates a
    /// capability offered by more than one provider.
    pub provider_id: Option<String>,
}

/// A named Recon Chain preset the caller can start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainKind {
    /// Fully offline invented discoveries (Phase 0). Requires example.test.
    Synthetic,
    /// First real chain (Phase 1A): passive subdomain discovery via Subfinder.
    DomainRecon,
}

impl Default for ChainKind {
    fn default() -> Self {
        Self::Synthetic
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderRun {
    pub id: Id,
    pub workspace_id: Id,
    pub chain_id: Id,
    pub stage_id: Id,
    pub provider_id: String,
    pub provider_version: String,
    pub target: String,
    pub start_time: String,
    pub end_time: Option<String>,
    pub status: TaskStatus,
    pub raw_output_reference: Option<Id>,
    pub exit_status: Option<i32>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: Id,
    pub workspace_id: Id,
    pub chain_id: Id,
    pub stage_id: Id,
    pub status: TaskStatus,
    pub updated_at: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub workspace: Workspace,
    pub targets: Vec<Target>,
    pub assets: Vec<Asset>,
    pub relationships: Vec<Relationship>,
    pub observations: Vec<Observation>,
    pub chains: Vec<ChainRun>,
    pub stages: Vec<Stage>,
    pub tasks: Vec<Task>,
    pub provider_runs: Vec<ProviderRun>,
    pub evidence: Vec<Evidence>,
    pub events: Vec<Event>,
    pub last_sequence: i64,
}

const CHAIN_SELECT:&str="SELECT json_object('id',id,'workspace_id',workspace_id,'target_id',target_id,'name',name,'status',status,'created_at',created_at,'updated_at',updated_at,'error_code',error_code) FROM chain_runs";
const STAGE_SELECT:&str="SELECT json_object('id',id,'workspace_id',workspace_id,'chain_id',chain_id,'position',position,'name',name,'capability',capability,'status',status,'started_at',started_at,'ended_at',ended_at,'provider_id',provider_id) FROM chain_stages";

impl Store {
    pub fn snapshot(&self, id: Id) -> Result<Snapshot> {
        let mut conn = self.connect(id)?;
        let tx = conn.transaction()?;
        let key = id.to_string();
        let mut events: Vec<Event> = rows(
            &tx,
            &format!("{EVENT_SELECT} WHERE workspace_id=?1 ORDER BY sequence DESC LIMIT 1000"),
            [&key],
        )?;
        events.reverse();
        let snapshot=Snapshot {
            workspace:database::workspace(&tx,id)?,targets:targets_in(&tx,id)?,assets:assets_in(&tx,id)?,
            relationships:rows(&tx,"SELECT json_object('id',id,'workspace_id',workspace_id,'source_asset_id',source_asset_id,'destination_asset_id',destination_asset_id,'relationship_type',relationship_type,'created_at',created_at) FROM asset_relationships WHERE workspace_id=?1 ORDER BY created_at,id",[&key])?,
            observations:rows(&tx,"SELECT json_object('id',id,'workspace_id',workspace_id,'asset_id',asset_id,'source_asset_id',source_asset_id,'provider_run_id',provider_run_id,'evidence_id',evidence_id,'discovered_by',discovered_by,'observed_value',observed_value,'timestamp',timestamp,'confidence',confidence) FROM observations WHERE workspace_id=?1 ORDER BY timestamp,id",[&key])?,
            chains:rows(&tx,&format!("{CHAIN_SELECT} WHERE workspace_id=?1 ORDER BY created_at,id"),[&key])?,
            stages:rows(&tx,&format!("{STAGE_SELECT} WHERE workspace_id=?1 ORDER BY chain_id,position"),[&key])?,
            tasks:rows(&tx,"SELECT json_object('id',id,'workspace_id',workspace_id,'chain_id',chain_id,'stage_id',stage_id,'status',status,'updated_at',updated_at) FROM tasks WHERE workspace_id=?1 ORDER BY updated_at,id",[&key])?,
            provider_runs:rows(&tx,"SELECT json_object('id',id,'workspace_id',workspace_id,'chain_id',chain_id,'stage_id',stage_id,'provider_id',provider_id,'provider_version',provider_version,'target',target,'start_time',start_time,'end_time',end_time,'status',status,'raw_output_reference',raw_output_reference,'exit_status',exit_status) FROM provider_runs WHERE workspace_id=?1 ORDER BY start_time,id",[&key])?,
            evidence:rows(&tx,&format!("{EVIDENCE_SELECT} WHERE workspace_id=?1 ORDER BY timestamp,id"),[&key])?,
            last_sequence:events.last().map_or(0,|e|e.sequence),events,
        };
        tx.commit()?;
        Ok(snapshot)
    }

    fn create_chain(&self, workspace: Id, target: Id, kind: ChainKind) -> Result<ChainRun> {
        let mut conn = self.connect(workspace)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let target = targets_in(&tx, workspace)?
            .into_iter()
            .find(|t| t.id == target)
            .ok_or_else(|| {
                CoreError::new("InvalidTarget", "Target does not exist in this workspace.")
            })?;
        // Each preset supplies a display name and its ordered stages. A stage
        // triple is (name, optional capability, optional pinned provider id).
        let (chain_name, stages): (&str, Vec<(&str, Option<Capability>, Option<&str>)>) = match kind
        {
            ChainKind::Synthetic => {
                if target.target_type != TargetType::Domain
                    || target.normalized_value != "example.test"
                {
                    return Err(CoreError::new(
                        "InvalidTarget",
                        "Synthetic Recon requires the domain example.test.",
                    ));
                }
                (
                    "Synthetic Recon",
                    vec![
                        ("Target Processing", None, None),
                        (
                            "Synthetic Subdomain Discovery",
                            Some(Capability::SubdomainDiscovery),
                            Some("synthetic"),
                        ),
                        (
                            "Synthetic Resolution",
                            Some(Capability::DnsResolution),
                            Some("synthetic"),
                        ),
                        (
                            "Synthetic Service Discovery",
                            Some(Capability::ServiceFingerprinting),
                            Some("synthetic"),
                        ),
                        ("Completion", None, None),
                    ],
                )
            }
            ChainKind::DomainRecon => {
                if target.target_type != TargetType::Domain {
                    return Err(CoreError::new(
                        "InvalidTarget",
                        "Domain Recon requires a domain target.",
                    ));
                }
                (
                    "Domain Recon",
                    vec![
                        ("Target Validation", None, None),
                        (
                            "Subfinder Discovery",
                            Some(Capability::SubdomainDiscovery),
                            Some("subfinder"),
                        ),
                        (
                            "DNS Resolution",
                            Some(Capability::DnsResolution),
                            Some("native_dns"),
                        ),
                        ("Persistence", None, None),
                        ("Completion", None, None),
                    ],
                )
            }
        };
        // Scope authorization is mandatory for every preset, real or synthetic.
        crate::scope::authorize(
            &database::workspace(&tx, workspace)?.scope,
            &target.normalized_value,
            crate::providers::RiskClass::Passive,
            false,
        )?;
        let count: i64 = tx.query_row("SELECT COUNT(*) FROM chain_runs", [], |r| r.get(0))?;
        if count >= 100 {
            return Err(CoreError::new(
                "BudgetExceeded",
                "The chain-run limit is 100 per workspace.",
            ));
        }
        let chain = ChainRun {
            id: Id::new_v4(),
            workspace_id: workspace,
            target_id: target.id,
            name: chain_name.into(),
            status: ChainStatus::Pending,
            created_at: crate::now(),
            updated_at: crate::now(),
            error_code: None,
        };
        tx.execute(
            "INSERT INTO chain_runs VALUES(?1,?2,?3,?4,'PENDING',?5,?5,NULL)",
            params![
                chain.id.to_string(),
                workspace.to_string(),
                target.id.to_string(),
                chain.name,
                chain.created_at
            ],
        )?;
        for (position, (name, capability, provider_id)) in stages.into_iter().enumerate() {
            let stage = Id::new_v4();
            tx.execute(
                "INSERT INTO chain_stages VALUES(?1,?2,?3,?4,?5,?6,'QUEUED',NULL,NULL,?7)",
                params![
                    stage.to_string(),
                    workspace.to_string(),
                    chain.id.to_string(),
                    position,
                    name,
                    capability.map(|v| encoded(&v)),
                    provider_id
                ],
            )?;
            tx.execute(
                "INSERT INTO tasks VALUES(?1,?2,?3,?4,'QUEUED',?5)",
                params![
                    Id::new_v4().to_string(),
                    workspace.to_string(),
                    chain.id.to_string(),
                    stage.to_string(),
                    crate::now()
                ],
            )?;
        }
        audit(&tx, workspace, "ReconStarted", chain.id)?;
        tx.commit()?;
        Ok(chain)
    }

    fn stage_transition(&self, workspace: Id, stage: Id, status: TaskStatus) -> Result<()> {
        let mut conn = self.connect(workspace)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: String = tx.query_row(
            "SELECT status FROM chain_stages WHERE workspace_id=?1 AND id=?2",
            params![workspace.to_string(), stage.to_string()],
            |r| r.get(0),
        )?;
        let current: TaskStatus = serde_json::from_value(json!(current))?;
        if !current.can_transition(status) {
            return Err(CoreError::new(
                "InvalidState",
                "Invalid task-state transition.",
            ));
        }
        let now = crate::now();
        tx.execute("UPDATE chain_stages SET status=?1,started_at=COALESCE(started_at,?2),ended_at=CASE WHEN ?1='RUNNING' THEN NULL ELSE ?2 END WHERE id=?3",
            params![encoded(&status),now,stage.to_string()])?;
        tx.execute(
            "UPDATE tasks SET status=?1,updated_at=?2 WHERE stage_id=?3",
            params![encoded(&status), now, stage.to_string()],
        )?;
        emit(
            &tx,
            workspace,
            EventType::TaskStatusChanged,
            json!({"stage_id":stage,"status":status}),
        )?;
        emit(
            &tx,
            workspace,
            if status == TaskStatus::Running {
                EventType::ChainStageStarted
            } else {
                EventType::ChainStageCompleted
            },
            json!({"stage_id":stage,"status":status}),
        )?;
        tx.commit()?;
        Ok(())
    }

    fn finish_chain(
        &self,
        workspace: Id,
        chain: Id,
        status: ChainStatus,
        error: Option<&str>,
    ) -> Result<()> {
        let mut conn = self.connect(workspace)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed=tx.execute("UPDATE chain_runs SET status=?1,updated_at=?2,error_code=?3 WHERE workspace_id=?4 AND id=?5 AND status IN ('PENDING','RUNNING')",
            params![encoded(&status),crate::now(),error,workspace.to_string(),chain.to_string()])?;
        if changed == 0 {
            return Ok(());
        }
        let task_status = if status == ChainStatus::Cancelled {
            "CANCELLED"
        } else {
            "FAILED"
        };
        let unfinished: Vec<Stage> = rows(
            &tx,
            &format!(
                "{STAGE_SELECT} WHERE chain_id=?1 AND status IN ('QUEUED','RUNNING','PAUSED')"
            ),
            [chain.to_string()],
        )?;
        for stage in unfinished {
            tx.execute(
                "UPDATE chain_stages SET status=?1,ended_at=?2 WHERE id=?3",
                params![task_status, crate::now(), stage.id.to_string()],
            )?;
            tx.execute(
                "UPDATE tasks SET status=?1,updated_at=?2 WHERE stage_id=?3",
                params![task_status, crate::now(), stage.id.to_string()],
            )?;
            emit(
                &tx,
                workspace,
                EventType::TaskStatusChanged,
                json!({"stage_id":stage.id,"status":task_status}),
            )?;
        }
        let active_runs: Vec<String> = {
            let mut statement =
                tx.prepare("SELECT id FROM provider_runs WHERE chain_id=?1 AND status='RUNNING'")?;
            let values = statement
                .query_map([chain.to_string()], |r| r.get(0))?
                .collect::<std::result::Result<_, _>>()?;
            values
        };
        for run in active_runs {
            tx.execute(
                "UPDATE provider_runs SET status=?1,end_time=?2,exit_status=1 WHERE id=?3",
                params![task_status, crate::now(), run],
            )?;
            emit(
                &tx,
                workspace,
                EventType::ProviderCompleted,
                json!({"provider_run_id":run,"status":task_status}),
            )?;
        }
        emit(
            &tx,
            workspace,
            if status == ChainStatus::Cancelled {
                EventType::ReconCancelled
            } else {
                EventType::ChainCompleted
            },
            json!({"chain_id":chain,"status":status,"error_code":error}),
        )?;
        if status == ChainStatus::Cancelled {
            audit(&tx, workspace, "ReconCancelled", chain)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn persist_discoveries(
        &self,
        workspace: Id,
        run: Id,
        evidence: Id,
        provider: &str,
        discoveries: &[Discovery],
    ) -> Result<()> {
        let mut conn = self.connect(workspace)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let scope = database::workspace(&tx, workspace)?.scope;
        let mut known: HashMap<String, Id> = assets_in(&tx, workspace)?
            .into_iter()
            .map(|a| (a.canonical_identity, a.id))
            .collect();
        for discovery in discoveries {
            let source = discovery
                .source
                .as_ref()
                .map(|s| {
                    let key = crate::targets::domain(s).unwrap_or_else(|_| s.to_owned());
                    known.get(&key).copied().ok_or_else(|| {
                        CoreError::new("ProviderFailure", "Discovery source is not a known asset.")
                    })
                })
                .transpose()?;
            if discovery.relationship.is_some() && source.is_none() {
                return Err(CoreError::new(
                    "ProviderFailure",
                    "A relationship requires a source asset.",
                ));
            }
            let mut metadata = discovery.metadata.clone();
            if !metadata.is_object() {
                return Err(CoreError::new(
                    "ProviderFailure",
                    "Asset metadata must be an object.",
                ));
            }
            let scope_value =
                if matches!(discovery.asset_type, AssetType::Port | AssetType::Service) {
                    metadata
                        .get("host")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            CoreError::new("ProviderFailure", "Service discoveries require a host.")
                        })?
                } else {
                    &discovery.value
                };
            let in_scope = crate::scope::contains(&scope, scope_value);
            metadata["in_scope"] = json!(in_scope);
            let asset = upsert_asset(
                &tx,
                workspace,
                discovery.asset_type,
                &discovery.value,
                metadata,
            )?;
            observe(
                &tx,
                &Observation {
                    id: Id::new_v4(),
                    workspace_id: workspace,
                    asset_id: asset.id,
                    source_asset_id: source,
                    provider_run_id: Some(run),
                    evidence_id: Some(evidence),
                    discovered_by: provider.into(),
                    observed_value: discovery.value.clone(),
                    timestamp: crate::now(),
                    confidence: "CONFIRMED".into(),
                },
            )?;
            if let (Some(source), Some(relation)) = (source, discovery.relationship) {
                let relation_name = encoded(&relation);
                let relation_id:Option<String>=tx.query_row("SELECT id FROM asset_relationships WHERE workspace_id=?1 AND source_asset_id=?2 AND destination_asset_id=?3 AND relationship_type=?4",
                    params![workspace.to_string(),source.to_string(),asset.id.to_string(),relation_name],|r|r.get(0)).optional()?;
                let is_new = relation_id.is_none();
                let id = relation_id.unwrap_or_else(|| Id::new_v4().to_string());
                if is_new {
                    tx.execute(
                        "INSERT INTO asset_relationships VALUES(?1,?2,?3,?4,?5,?6)",
                        params![
                            id,
                            workspace.to_string(),
                            source.to_string(),
                            asset.id.to_string(),
                            relation_name,
                            crate::now()
                        ],
                    )?;
                    emit(
                        &tx,
                        workspace,
                        EventType::RelationshipCreated,
                        json!({"relationship_id":id,"source_asset_id":source,"destination_asset_id":asset.id,"relationship_type":relation}),
                    )?;
                }
                tx.execute(
                    "INSERT INTO relationship_observations VALUES(?1,?2,?3,?4,?5,?6)",
                    params![
                        Id::new_v4().to_string(),
                        workspace.to_string(),
                        id,
                        run.to_string(),
                        evidence.to_string(),
                        crate::now()
                    ],
                )?;
            }
            known.insert(asset.canonical_identity, asset.id);
        }
        tx.commit()?;
        Ok(())
    }
}

use rusqlite::OptionalExtension;

struct ActiveRun {
    workspace: Id,
    chain: Id,
    cancelled: Arc<AtomicBool>,
}
#[derive(Clone)]
pub struct Engine {
    pub store: Store,
    registry: ProviderRegistry,
    tools: crate::process::ToolConfig,
    active: Arc<Mutex<Option<ActiveRun>>>,
    _lock: Arc<File>,
    stage_delay: Duration,
}

impl Engine {
    /// Open an engine, discovering external tools from the environment.
    pub fn open(store: Store, stage_delay: Duration) -> Result<Self> {
        Self::open_with_tools(store, stage_delay, crate::process::ToolConfig::from_env())
    }

    /// Open an engine with an explicit tool configuration, selecting the DNS
    /// resolver from the environment (`MACSPLOIT_DNS_FAKE` for offline runs).
    pub fn open_with_tools(
        store: Store,
        stage_delay: Duration,
        tools: crate::process::ToolConfig,
    ) -> Result<Self> {
        Self::open_with(store, stage_delay, tools, crate::dns::resolver_from_env())
    }

    /// Open an engine with an explicit tool configuration and DNS resolver. Tests
    /// use this to inject a fake executable and a static, offline DNS resolver.
    pub fn open_with(
        store: Store,
        stage_delay: Duration,
        tools: crate::process::ToolConfig,
        resolver: Arc<dyn crate::dns::DnsResolver>,
    ) -> Result<Self> {
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(store.root.join("core.lock"))?;
        lock.try_lock().map_err(|_| {
            CoreError::new(
                "CoreBusy",
                "Another core helper already owns this storage directory.",
            )
        })?;
        let engine = Self {
            store,
            registry: ProviderRegistry::new(resolver),
            tools,
            active: Arc::new(Mutex::new(None)),
            _lock: Arc::new(lock),
            stage_delay,
        };
        for workspace in engine.store.list_workspaces()? {
            let snapshot = engine.store.snapshot(workspace.id)?;
            for chain in snapshot
                .chains
                .iter()
                .filter(|c| matches!(c.status, ChainStatus::Pending | ChainStatus::Running))
            {
                engine.store.finish_chain(
                    workspace.id,
                    chain.id,
                    ChainStatus::Failed,
                    Some("Interrupted"),
                )?;
                let mut conn = engine.store.connect(workspace.id)?;
                let tx = conn.transaction()?;
                emit(
                    &tx,
                    workspace.id,
                    EventType::RecoveryCompleted,
                    json!({"chain_id":chain.id,"reason":"Interrupted"}),
                )?;
                tx.commit()?;
            }
        }
        Ok(engine)
    }

    pub fn providers(&self) -> Vec<crate::providers::ProviderStatus> {
        self.registry.status(&self.tools)
    }

    pub fn start(&self, workspace: Id, target: Id, kind: ChainKind) -> Result<ChainRun> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| CoreError::new("InternalError", "Task coordinator unavailable."))?;
        if active.is_some() {
            return Err(CoreError::new(
                "CoreBusy",
                "One Recon Chain is already running. Wait or cancel it.",
            ));
        }
        let chain = self.store.create_chain(workspace, target, kind)?;
        let cancellation = Arc::new(AtomicBool::new(false));
        *active = Some(ActiveRun {
            workspace,
            chain: chain.id,
            cancelled: cancellation.clone(),
        });
        let engine = self.clone();
        let worker_chain = chain.clone();
        thread::spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                engine.execute(&worker_chain, &cancellation)
            }));
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    let state = if error.code == "Cancelled" {
                        ChainStatus::Cancelled
                    } else {
                        ChainStatus::Failed
                    };
                    let _ = engine.store.finish_chain(
                        workspace,
                        worker_chain.id,
                        state,
                        Some(&error.code),
                    );
                }
                Err(_) => {
                    let _ = engine.store.finish_chain(
                        workspace,
                        worker_chain.id,
                        ChainStatus::Failed,
                        Some("InternalError"),
                    );
                }
            }
            if let Ok(mut active) = engine.active.lock() {
                *active = None;
            }
        });
        Ok(chain)
    }

    pub fn cancel(&self, workspace: Id, chain: Id) -> Result<()> {
        let active = self
            .active
            .lock()
            .map_err(|_| CoreError::new("InternalError", "Task coordinator unavailable."))?;
        let Some(run) = active
            .as_ref()
            .filter(|run| run.workspace == workspace && run.chain == chain)
        else {
            return Err(CoreError::new(
                "InvalidState",
                "This Recon Chain is not running.",
            ));
        };
        run.cancelled.store(true, Ordering::SeqCst);
        Ok(())
    }

    pub fn idle(&self) -> bool {
        self.active.lock().map(|a| a.is_none()).unwrap_or(false)
    }

    pub fn shutdown(&self) {
        if let Ok(active) = self.active.lock() {
            if let Some(run) = active.as_ref() {
                run.cancelled.store(true, Ordering::SeqCst);
            }
        }
        let deadline = Instant::now() + Duration::from_secs(6);
        while !self.idle() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn execute(&self, chain: &ChainRun, cancelled: &AtomicBool) -> Result<()> {
        let workspace = chain.workspace_id;
        let snapshot = self.store.snapshot(workspace)?;
        let target = snapshot
            .targets
            .iter()
            .find(|t| t.id == chain.target_id)
            .ok_or_else(|| CoreError::new("InvalidTarget", "Target missing."))?;
        let mut conn = self.store.connect(workspace)?;
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE chain_runs SET status='RUNNING',updated_at=?1 WHERE id=?2",
            params![crate::now(), chain.id.to_string()],
        )?;
        emit(
            &tx,
            workspace,
            EventType::ChainStarted,
            json!({"chain_id":chain.id,"target":target.normalized_value}),
        )?;
        tx.commit()?;
        let started = Instant::now();
        for stage in snapshot.stages.iter().filter(|s| s.chain_id == chain.id) {
            self.check_budget(cancelled, started)?;
            self.store
                .stage_transition(workspace, stage.id, TaskStatus::Running)?;
            let until = Instant::now() + self.stage_delay;
            while Instant::now() < until {
                self.check_budget(cancelled, started)?;
                thread::sleep(Duration::from_millis(10));
            }
            if let Some(capability) = stage.capability {
                self.execute_provider(chain, stage, target, capability, cancelled, started)?;
            }
            self.check_budget(cancelled, started)?;
            self.store
                .stage_transition(workspace, stage.id, TaskStatus::Completed)?;
        }
        self.store
            .finish_chain(workspace, chain.id, ChainStatus::Completed, None)
    }

    fn check_budget(&self, cancelled: &AtomicBool, started: Instant) -> Result<()> {
        if cancelled.load(Ordering::SeqCst) {
            return Err(CoreError::new("Cancelled", "Recon Chain cancelled."));
        }
        if started.elapsed() > Duration::from_secs(30) {
            return Err(CoreError::new(
                "BudgetExceeded",
                "Recon Chain exceeded 30 seconds.",
            ));
        }
        Ok(())
    }

    fn execute_provider(
        &self,
        chain: &ChainRun,
        stage: &Stage,
        target: &Target,
        capability: Capability,
        cancelled: &AtomicBool,
        started: Instant,
    ) -> Result<()> {
        let workspace = chain.workspace_id;
        // Pin the exact provider when the stage names one; otherwise fall back to
        // capability-based selection (preserves earlier single-provider behavior).
        let provider = match &stage.provider_id {
            Some(id) => self.registry.named(id, capability, target.target_type)?,
            None => self.registry.select(capability, target.target_type)?,
        };
        let metadata = provider.metadata();
        let conn = self.store.connect(workspace)?;
        let scope = database::workspace(&conn, workspace)?.scope;
        crate::scope::authorize(&scope, &target.normalized_value, metadata.risk_class, false)?;
        let mut inputs:Vec<Asset>=rows(&conn,&format!("{ASSET_SELECT} WHERE workspace_id=?1 AND (id=?2 OR id IN (SELECT asset_id FROM observations o JOIN provider_runs p ON p.id=o.provider_run_id WHERE p.chain_id=?3))"),
            params![workspace.to_string(),target.asset_id.map(|id|id.to_string()),chain.id.to_string()])?;
        inputs.retain(|a| crate::scope::contains(&scope, &a.canonical_identity));
        drop(conn);

        // Detect the tool and its version before recording the run, so the run is
        // reproducible ("which version produced this?"). A missing or unusable
        // tool fails the run cleanly with a surfaced code — it never crashes.
        let version = match provider.installation(&self.tools) {
            // Built-in providers report the core version so runs stay reproducible.
            crate::process::Installation::BuiltIn => {
                format!("core {}", env!("CARGO_PKG_VERSION"))
            }
            crate::process::Installation::Installed { version } => version,
            crate::process::Installation::Missing => {
                return Err(CoreError::new(
                    "ProviderMissing",
                    "The provider tool is not installed. Install it to run this chain.",
                ))
            }
            crate::process::Installation::UnsupportedVersion { .. } => {
                return Err(CoreError::new(
                    "ProviderUnsupported",
                    "The installed provider version is not supported.",
                ))
            }
            crate::process::Installation::ExecutionError { message } => {
                return Err(CoreError::new(
                    "ProviderFailure",
                    &format!("The provider tool could not be inspected: {message}"),
                ))
            }
        };

        let run = Id::new_v4();
        let mut conn = self.store.connect(workspace)?;
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO provider_runs VALUES(?1,?2,?3,?4,?5,?6,?7,?8,NULL,'RUNNING',NULL,NULL)",
            params![
                run.to_string(),
                workspace.to_string(),
                chain.id.to_string(),
                stage.id.to_string(),
                metadata.id,
                version,
                target.normalized_value,
                crate::now()
            ],
        )?;
        emit(
            &tx,
            workspace,
            EventType::ProviderStarted,
            json!({"provider_run_id":run,"provider":metadata.name,"capability":capability}),
        )?;
        tx.commit()?;

        // The provider deadline never outlives the chain budget.
        let deadline = started + Duration::from_secs(30);
        let ctx = crate::providers::ProviderContext {
            cancelled,
            deadline,
            tools: &self.tools,
        };
        let execution = provider.execute(&target.normalized_value, capability, &inputs, &ctx)?;

        // Preserve the complete provider output (stdout, stderr, command, exit,
        // timings, version) as an evidence envelope BEFORE parsing, so neither a
        // tool failure nor a parser failure can destroy the raw record.
        let envelope = serde_json::to_vec_pretty(&json!({
            "provider": metadata.id,
            "provider_name": metadata.name,
            "provider_version": version,
            "offline": metadata.offline,
            "capability": capability,
            "target": execution.target,
            "command": execution.command,
            "exit_status": execution.exit_status,
            "timed_out": execution.timed_out,
            "pid": execution.pid,
            "started_at": execution.started_at,
            "ended_at": execution.ended_at,
            "stdout": String::from_utf8_lossy(&execution.stdout),
            "stderr": String::from_utf8_lossy(&execution.stderr),
        }))?;
        let evidence = self.store.write_evidence(
            workspace,
            run,
            &metadata.name,
            &target.normalized_value,
            &envelope,
        )?;
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO evidence VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                evidence.id.to_string(),
                workspace.to_string(),
                run.to_string(),
                evidence.provider,
                evidence.target,
                evidence.timestamp,
                evidence.sha256,
                evidence.media_type,
                evidence.relative_path,
                evidence.byte_count
            ],
        )?;
        tx.execute(
            "UPDATE provider_runs SET raw_output_reference=?1 WHERE id=?2",
            params![evidence.id.to_string(), run.to_string()],
        )?;
        emit(
            &tx,
            workspace,
            EventType::EvidenceCreated,
            json!({"evidence_id":evidence.id,"provider_run_id":run}),
        )?;
        tx.commit()?;

        // A tool that timed out or exited non-zero is a failed run, but its
        // evidence is already durable. Mark it and fail the chain gracefully.
        if !execution.succeeded() {
            let tx = conn.transaction()?;
            tx.execute(
                "UPDATE provider_runs SET end_time=?1,status='FAILED',exit_status=?2 WHERE id=?3",
                params![crate::now(), execution.exit_status, run.to_string()],
            )?;
            emit(
                &tx,
                workspace,
                EventType::ProviderCompleted,
                json!({"provider_run_id":run,"provider":metadata.name,"status":"FAILED"}),
            )?;
            tx.commit()?;
            return Err(CoreError::new(
                if execution.timed_out {
                    "ProviderTimeout"
                } else {
                    "ProviderFailure"
                },
                "The provider process did not complete successfully.",
            ));
        }

        self.check_budget(cancelled, started)?;
        let discoveries = provider.parse(&execution)?;
        self.store.persist_discoveries(
            workspace,
            run,
            evidence.id,
            &metadata.name,
            &discoveries,
        )?;
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE provider_runs SET end_time=?1,status='COMPLETED',exit_status=0 WHERE id=?2",
            params![crate::now(), run.to_string()],
        )?;
        emit(
            &tx,
            workspace,
            EventType::ProviderCompleted,
            json!({"provider_run_id":run,"provider":metadata.name,"status":"COMPLETED"}),
        )?;
        tx.commit()?;
        Ok(())
    }
}
