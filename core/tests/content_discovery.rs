//! Phase 2C end-to-end coverage for content discovery (ffuf), driven entirely
//! offline through a fake executable and a static wordlist fixture. No network.

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

fn tools_with_ffuf() -> ToolConfig {
    let mut tools = ToolConfig::default();
    tools
        .overrides
        .insert("ffuf".into(), fixture("fake-ffuf.sh"));
    tools
}

fn engine(tools: ToolConfig) -> (tempfile::TempDir, Engine, Id, Id) {
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::open_with(
        Store::open(temp.path()).unwrap(),
        Duration::ZERO,
        tools,
        Arc::new(StaticDnsResolver::new()),
    )
    .unwrap();
    let workspace = engine
        .store
        .create_workspace("Content", &["example.test".into(), "*.example.test".into()])
        .unwrap();
    let target = engine
        .store
        .add_target(workspace.id, "https://example.test/")
        .unwrap();
    (temp, engine, workspace.id, target.id)
}

fn wordlist_option() -> serde_json::Value {
    serde_json::json!({ "wordlist_path": fixture("content-discovery-small.txt").to_string_lossy() })
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
fn content_discovery_runs_ffuf_end_to_end_and_persists() {
    let (temp, engine, workspace, target) = engine(tools_with_ffuf());
    engine
        .start(
            workspace,
            target,
            ChainKind::ContentDiscovery,
            wordlist_option(),
        )
        .unwrap();
    let snapshot = wait(&engine, workspace);

    assert_eq!(snapshot.chains[0].name, "Content Discovery");
    assert_eq!(snapshot.chains[0].status, ChainStatus::Completed);
    assert!(snapshot
        .stages
        .iter()
        .any(|s| s.name == "Content Discovery" && s.provider_id.as_deref() == Some("ffuf")));

    // Discovered URL assets: admin/login/api/secret (404 "missing" excluded).
    let urls: Vec<_> = snapshot
        .assets
        .iter()
        .filter(|a| {
            a.asset_type == AssetType::URL && a.canonical_identity != "https://example.test/"
        })
        .map(|a| a.canonical_identity.as_str())
        .collect();
    assert_eq!(urls.len(), 4, "got {urls:?}");
    for expected in [
        "https://example.test/admin",
        "https://example.test/login",
        "https://example.test/api",
        "https://example.test/secret",
    ] {
        assert!(urls.contains(&expected), "missing {expected}");
    }
    assert!(!urls.iter().any(|u| u.contains("missing"))); // 404 created no asset

    // has_endpoint relationships from the root URL to each discovery.
    assert_eq!(
        snapshot
            .relationships
            .iter()
            .filter(|r| r.relationship_type == RelationshipType::HasEndpoint)
            .count(),
        4
    );

    // One ffuf provider run, completed, with detected version.
    assert_eq!(snapshot.provider_runs.len(), 1);
    let run = &snapshot.provider_runs[0];
    assert_eq!(run.provider_id, "ffuf");
    assert_eq!(run.provider_version, "2.1.0");

    // Evidence redacts the local wordlist path to its file name only.
    assert_eq!(snapshot.evidence.len(), 1);
    let raw = engine
        .store
        .read_evidence(workspace, snapshot.evidence[0].id)
        .unwrap();
    assert!(raw.contains("content-discovery-small.txt")); // basename kept for provenance
    assert!(!raw.contains("/fixtures/content-discovery-small.txt")); // full path redacted
    assert!(raw.contains("example.test/admin"));

    // Persistence across reopen.
    drop(engine);
    let reopened = Engine::open_with(
        Store::open(temp.path()).unwrap(),
        Duration::ZERO,
        ToolConfig::default(),
        Arc::new(StaticDnsResolver::new()),
    )
    .unwrap();
    let after = reopened.store.snapshot(workspace).unwrap();
    assert_eq!(
        after
            .assets
            .iter()
            .filter(|a| a.asset_type == AssetType::URL)
            .count(),
        5 // root + 4 discoveries
    );
    assert_eq!(after.provider_runs.len(), 1);
    assert_eq!(after.evidence.len(), 1);
    assert_eq!(after.chains[0].status, ChainStatus::Completed);
}

#[test]
fn content_discovery_runs_against_an_explicitly_scoped_localhost_target() {
    // ffuf path discovery over a locally running app, authorized by an explicit
    // `localhost` scope entry. Custom port is preserved and evidence stays redacted.
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::open_with(
        Store::open(temp.path()).unwrap(),
        Duration::ZERO,
        tools_with_ffuf(),
        Arc::new(StaticDnsResolver::new()),
    )
    .unwrap();
    let workspace = engine
        .store
        .create_workspace("Local App", &["localhost".into()])
        .unwrap();
    let target = engine
        .store
        .add_target(workspace.id, "http://localhost:3000/")
        .unwrap();

    engine
        .start(
            workspace.id,
            target.id,
            ChainKind::ContentDiscovery,
            wordlist_option(),
        )
        .unwrap();
    let snapshot = wait(&engine, workspace.id);

    assert_eq!(snapshot.chains[0].status, ChainStatus::Completed);
    let urls: Vec<_> = snapshot
        .assets
        .iter()
        .filter(|a| {
            a.asset_type == AssetType::URL && a.canonical_identity != "http://localhost:3000/"
        })
        .map(|a| a.canonical_identity.as_str())
        .collect();
    assert_eq!(urls.len(), 4, "got {urls:?}");
    for expected in [
        "http://localhost:3000/admin",
        "http://localhost:3000/login",
        "http://localhost:3000/api",
        "http://localhost:3000/secret",
    ] {
        assert!(urls.contains(&expected), "missing {expected}");
    }

    // Wordlist path is still redacted to its file name for a local target.
    let raw = engine
        .store
        .read_evidence(workspace.id, snapshot.evidence[0].id)
        .unwrap();
    assert!(raw.contains("content-discovery-small.txt"));
    assert!(!raw.contains("/fixtures/content-discovery-small.txt"));
}

#[test]
fn content_discovery_requires_a_wordlist() {
    let (_temp, engine, workspace, target) = engine(tools_with_ffuf());
    let error = engine
        .start(
            workspace,
            target,
            ChainKind::ContentDiscovery,
            serde_json::json!({}),
        )
        .unwrap_err();
    assert_eq!(error.code, "WordlistMissing");
}

#[test]
fn content_discovery_requires_in_scope_url() {
    let (_temp, engine, workspace, _target) = engine(tools_with_ffuf());
    let outside = engine
        .store
        .add_target(workspace, "https://other.test/")
        .unwrap();
    let error = engine
        .start(
            workspace,
            outside.id,
            ChainKind::ContentDiscovery,
            wordlist_option(),
        )
        .unwrap_err();
    assert_eq!(error.code, "ScopeViolation");
}
