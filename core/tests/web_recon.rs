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
fn provider_command_event_redacts_url_query_but_execution_keeps_it() {
    // The execution argv must keep the full target URL (including a secret query), while
    // the durable ProviderCommand display event must not leak the query value.
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
        .create_workspace("Web", &["app.example.test".into()])
        .unwrap();
    let target = engine
        .store
        .add_target(
            workspace.id,
            "https://app.example.test/search?token=secret-value&debug=1",
        )
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
    assert_eq!(snapshot.chains[0].status, ChainStatus::Completed);

    // Execution record (evidence envelope) keeps the exact argv, query included.
    let raw = engine
        .store
        .read_evidence(workspace.id, snapshot.evidence[0].id)
        .unwrap();
    assert!(
        raw.contains("token=secret-value"),
        "execution argv must be unchanged"
    );

    // The ProviderCommand display event redacts the query and never carries the secret.
    let command_event = snapshot
        .events
        .iter()
        .find(|e| e.event_type == macsploit_core::events::EventType::ProviderCommand)
        .expect("ProviderCommand event");
    let shown = command_event.payload.to_string();
    assert!(
        !shown.contains("secret-value"),
        "display must not leak the query value"
    );
    assert!(!shown.contains("debug=1"));
    assert!(shown.contains("?<redacted>"));
    assert!(shown.contains("app.example.test")); // host context preserved
}

#[test]
fn web_recon_crawls_an_explicitly_scoped_localhost_target() {
    // A locally running app, authorized by an explicit `localhost` scope entry, with no
    // public DNS and no Domain target. Custom port is preserved; distinct hosts dropped.
    let temp = tempfile::tempdir().unwrap();
    let mut tools = ToolConfig::default();
    tools
        .overrides
        .insert("katana".into(), fixture("fake-katana-local.sh"));

    let engine = Engine::open_with(
        Store::open(temp.path()).unwrap(),
        Duration::ZERO,
        tools,
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
            ChainKind::WebRecon,
            serde_json::Value::Null,
        )
        .unwrap();
    let snapshot = wait(&engine, workspace.id);

    assert_eq!(snapshot.chains[0].status, ChainStatus::Completed);
    let urls: Vec<_> = snapshot
        .assets
        .iter()
        .filter(|a| a.asset_type == AssetType::URL)
        .map(|a| a.canonical_identity.as_str())
        .collect();
    assert!(urls.contains(&"http://localhost:3000/login"));
    assert!(urls.contains(&"http://localhost:3000/dashboard"));
    // A distinct loopback host and an off-host URL are never recorded.
    assert!(!urls.iter().any(|u| u.contains("127.0.0.1")));
    assert!(!urls.iter().any(|u| u.contains("evil.test")));
    assert_eq!(
        snapshot
            .relationships
            .iter()
            .filter(|r| r.relationship_type == RelationshipType::HasEndpoint)
            .count(),
        2
    );
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
