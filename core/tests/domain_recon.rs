//! Phase 1A end-to-end coverage for the first real provider (Subfinder), driven
//! entirely offline through a fake executable. No network access occurs.

use macsploit_core::{
    assets::{AssetType, Id},
    database::Store,
    events::{ChainStatus, TaskStatus},
    orchestration::{ChainKind, Engine, Snapshot},
    process::ToolConfig,
};
use std::{
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

fn fake_subfinder() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/fake-subfinder.sh")
        .canonicalize()
        .expect("fake subfinder fixture exists")
}

fn tools_with_subfinder(path: PathBuf) -> ToolConfig {
    let mut tools = ToolConfig::default();
    tools.overrides.insert("subfinder".into(), path);
    tools
}

fn engine_with(tools: ToolConfig) -> (tempfile::TempDir, Engine, Id, Id) {
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::open_with_tools(Store::open(temp.path()).unwrap(), Duration::ZERO, tools).unwrap();
    let workspace = engine
        .store
        .create_workspace(
            "Domain Assessment",
            &["example.test".into(), "*.example.test".into()],
        )
        .unwrap();
    let target = engine.store.add_target(workspace.id, "example.test").unwrap();
    (temp, engine, workspace.id, target.id)
}

fn wait(engine: &Engine, workspace: Id) -> Snapshot {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !engine.idle() {
        assert!(Instant::now() < deadline, "chain timed out");
        thread::sleep(Duration::from_millis(5));
    }
    engine.store.snapshot(workspace).unwrap()
}

#[test]
fn domain_recon_runs_subfinder_end_to_end_and_persists() {
    let (temp, engine, workspace, target) = engine_with(tools_with_subfinder(fake_subfinder()));
    let chain = engine
        .start(workspace, target, ChainKind::DomainRecon)
        .unwrap();
    let snapshot = wait(&engine, workspace);

    // Chain shape.
    assert_eq!(snapshot.chains[0].id, chain.id);
    assert_eq!(snapshot.chains[0].name, "Domain Recon");
    assert_eq!(snapshot.chains[0].status, ChainStatus::Completed);
    assert!(snapshot.stages.iter().all(|s| s.status == TaskStatus::Completed));
    assert!(snapshot
        .stages
        .iter()
        .any(|s| s.name == "Subfinder Discovery" && s.provider_id.as_deref() == Some("subfinder")));

    // Assets: apex domain + three de-duplicated subdomains (api/dev/auth).
    let subdomains: Vec<_> = snapshot
        .assets
        .iter()
        .filter(|a| a.asset_type == AssetType::Subdomain)
        .map(|a| a.canonical_identity.as_str())
        .collect();
    assert_eq!(subdomains.len(), 3, "got {subdomains:?}");
    for expected in ["api.example.test", "dev.example.test", "auth.example.test"] {
        assert!(subdomains.contains(&expected), "missing {expected}");
    }
    // Every discovered subdomain is in scope and marked so.
    for asset in snapshot
        .assets
        .iter()
        .filter(|a| a.asset_type == AssetType::Subdomain)
    {
        assert_eq!(asset.metadata["in_scope"], serde_json::json!(true));
        assert_eq!(asset.metadata["tool"], serde_json::json!("subfinder"));
    }

    // Relationships: three has_subdomain edges from the apex.
    assert_eq!(snapshot.relationships.len(), 3);
    assert!(snapshot
        .relationships
        .iter()
        .all(|r| r.relationship_type == macsploit_core::assets::RelationshipType::HasSubdomain));

    // Provider run: one real subfinder run, completed, with detected version and
    // an evidence reference.
    assert_eq!(snapshot.provider_runs.len(), 1);
    let run = &snapshot.provider_runs[0];
    assert_eq!(run.provider_id, "subfinder");
    assert_eq!(run.provider_version, "9.9.9");
    assert_eq!(run.status, TaskStatus::Completed);
    assert_eq!(run.exit_status, Some(0));
    assert!(run.raw_output_reference.is_some());

    // Provenance: each subdomain observation is attributed to Subfinder, the
    // provider run, and evidence.
    for observation in snapshot
        .observations
        .iter()
        .filter(|o| o.discovered_by == "Subfinder")
    {
        assert_eq!(observation.provider_run_id, Some(run.id));
        assert!(observation.evidence_id.is_some());
    }

    // Evidence envelope preserves the raw tool output and command.
    assert_eq!(snapshot.evidence.len(), 1);
    let raw = engine
        .store
        .read_evidence(workspace, snapshot.evidence[0].id)
        .unwrap();
    let envelope: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(envelope["provider"], "subfinder");
    assert_eq!(envelope["provider_version"], "9.9.9");
    assert_eq!(envelope["offline"], false);
    assert!(envelope["command"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "-oJ"));
    assert!(envelope["stdout"].as_str().unwrap().contains("api.example.test"));

    // Events include the real provider lifecycle.
    let event_types: Vec<_> = snapshot
        .events
        .iter()
        .map(|e| serde_json::to_value(e.event_type).unwrap())
        .collect();
    for expected in ["ProviderStarted", "ProviderCompleted", "ChainCompleted"] {
        assert!(
            event_types.iter().any(|t| t == expected),
            "missing event {expected}"
        );
    }

    // Persistence across a database reopen.
    drop(engine);
    let reopened = Engine::open_with_tools(
        Store::open(temp.path()).unwrap(),
        Duration::ZERO,
        ToolConfig::default(),
    )
    .unwrap();
    let after = reopened.store.snapshot(workspace).unwrap();
    assert_eq!(after.assets.len(), snapshot.assets.len());
    assert_eq!(after.relationships.len(), snapshot.relationships.len());
    assert_eq!(after.provider_runs.len(), 1);
    assert_eq!(after.evidence.len(), 1);
    assert_eq!(after.chains[0].status, ChainStatus::Completed);
    // Evidence remains hash-verifiable after reopen.
    assert!(reopened
        .store
        .read_evidence(workspace, after.evidence[0].id)
        .is_ok());
}

#[test]
fn domain_recon_fails_cleanly_when_subfinder_is_missing() {
    // Point the tool at a nonexistent path so it is reliably "missing".
    let (_temp, engine, workspace, target) =
        engine_with(tools_with_subfinder(PathBuf::from("/nonexistent/subfinder")));
    engine
        .start(workspace, target, ChainKind::DomainRecon)
        .unwrap();
    let snapshot = wait(&engine, workspace);
    let chain = &snapshot.chains[0];
    assert_eq!(chain.status, ChainStatus::Failed);
    assert_eq!(chain.error_code.as_deref(), Some("ProviderMissing"));
    // No assets or evidence were fabricated for a run that never happened.
    assert!(snapshot
        .assets
        .iter()
        .all(|a| a.asset_type != AssetType::Subdomain));
    assert!(snapshot.evidence.is_empty());
}

#[test]
fn domain_recon_requires_target_in_scope() {
    let (_temp, engine, workspace, _target) = engine_with(tools_with_subfinder(fake_subfinder()));
    // A domain outside the workspace scope must be refused before execution.
    let outside = engine.store.add_target(workspace, "other.test").unwrap();
    let error = engine
        .start(workspace, outside.id, ChainKind::DomainRecon)
        .unwrap_err();
    assert_eq!(error.code, "ScopeViolation");
}
