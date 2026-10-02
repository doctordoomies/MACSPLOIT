//! Phase 2A Web Recon coverage. Uses an offline fake Katana executable only.

use macsploit_core::{
    assets::{AssetType, Id, RelationshipType},
    database::Store,
    dns::StaticDnsResolver,
    events::ChainStatus,
    orchestration::{ChainKind, Engine, Snapshot},
    process::ToolConfig,
};
use std::{
    path::PathBuf,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures")
        .join(name)
        .canonicalize()
        .unwrap_or_else(|_| panic!("fixture {name} exists"))
}

fn wait(engine: &Engine, workspace: Id) -> Snapshot {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !engine.idle() {
        assert!(Instant::now() < deadline, "chain timed out");
        thread::sleep(Duration::from_millis(5));
    }
    engine.store.snapshot(workspace).unwrap()
}

#[test]
fn web_recon_crawls_same_host_and_persists_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let mut tools = ToolConfig::default();
    tools
        .overrides
        .insert("katana".into(), fixture("fake-katana.sh"));

    let engine = Engine::open_with(
        Store::open(temp.path()).unwrap(),
        Duration::ZERO,
        tools,
        Arc::new(StaticDnsResolver::new()),
    )
    .unwrap();
    let workspace = engine
        .store
        .create_workspace(
            "Web Assessment",
            &["example.test".into(), "*.example.test".into()],
        )
        .unwrap();
    let target = engine
        .store
        .add_target(workspace.id, "https://app.example.test/")
        .unwrap();

    engine
        .start(
            workspace.id,
            target.id,
            ChainKind::WebRecon,
            serde_json::Value::Null,
        )
        .unwrap();
    let snapshot = wait(&engine, workspace.id);

    assert_eq!(snapshot.chains[0].name, "Web Recon");
    assert_eq!(snapshot.chains[0].status, ChainStatus::Completed);
    assert_eq!(snapshot.provider_runs.len(), 1);
    assert_eq!(snapshot.provider_runs[0].provider_id, "katana");
    assert_eq!(snapshot.evidence.len(), 1);

    let urls: Vec<_> = snapshot
        .assets
        .iter()
        .filter(|a| a.asset_type == AssetType::URL)
        .map(|a| a.canonical_identity.as_str())
        .collect();
    assert!(urls.contains(&"https://app.example.test/"));
    assert!(urls.contains(&"https://app.example.test/login"));
    assert!(urls.contains(&"https://app.example.test/api/users?x=1"));
    assert!(!urls.iter().any(|url| url.contains("outside.test")));

    let endpoint_links = snapshot
        .relationships
        .iter()
        .filter(|r| r.relationship_type == RelationshipType::HasEndpoint)
        .count();
    assert_eq!(endpoint_links, 2);

    let evidence = &snapshot.evidence[0];
    let raw = engine
        .store
        .read_evidence(workspace.id, evidence.id)
        .unwrap();
    assert!(raw.contains("app.example.test/login"));
    assert!(raw.contains("outside.test"));
}

#[test]
fn web_recon_requires_url_target() {
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::open_with(
        Store::open(temp.path()).unwrap(),
        Duration::ZERO,
        ToolConfig::default(),
        Arc::new(StaticDnsResolver::new()),
    )
    .unwrap();
    let workspace = engine
        .store
        .create_workspace("Web Assessment", &["example.test".into()])
        .unwrap();
    let target = engine
        .store
        .add_target(workspace.id, "example.test")
        .unwrap();

    let error = engine
        .start(
            workspace.id,
            target.id,
            ChainKind::WebRecon,
            serde_json::Value::Null,
        )
        .unwrap_err();
    assert_eq!(error.code, "InvalidTarget");
}
