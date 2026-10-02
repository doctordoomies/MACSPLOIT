//! End-to-end coverage for the built-in DNS Recon chain.
//! Uses a static resolver so the automated suite performs no network activity.

use macsploit_core::{
    assets::{AssetType, Id},
    database::Store,
    dns::StaticDnsResolver,
    events::{ChainStatus, TaskStatus},
    orchestration::{ChainKind, Engine, Snapshot},
    process::ToolConfig,
};
use std::{
    net::Ipv4Addr,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

fn wait(engine: &Engine, workspace: Id) -> Snapshot {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !engine.idle() {
        assert!(Instant::now() < deadline, "DNS Recon timed out");
        thread::sleep(Duration::from_millis(5));
    }
    engine.store.snapshot(workspace).unwrap()
}

#[test]
fn dns_recon_is_useful_without_external_tools() {
    let temp = tempfile::tempdir().unwrap();
    let resolver = StaticDnsResolver::new().with(
        "example.test",
        &["192.0.2.20".parse::<Ipv4Addr>().unwrap()],
        &[],
    );
    let engine = Engine::open_with(
        Store::open(temp.path()).unwrap(),
        Duration::ZERO,
        ToolConfig::default(),
        Arc::new(resolver),
    )
    .unwrap();

    let workspace = engine
        .store
        .create_workspace(
            "Native DNS",
            &["example.test".into(), "192.0.2.0/24".into()],
        )
        .unwrap();
    let target = engine
        .store
        .add_target(workspace.id, "example.test")
        .unwrap();

    let chain = engine
        .start(workspace.id, target.id, ChainKind::DnsRecon)
        .unwrap();
    let snapshot = wait(&engine, workspace.id);

    let stored = snapshot
        .chains
        .iter()
        .find(|candidate| candidate.id == chain.id)
        .unwrap();
    assert_eq!(stored.name, "DNS Recon");
    assert_eq!(stored.status, ChainStatus::Completed);

    let stages: Vec<_> = snapshot
        .stages
        .iter()
        .filter(|stage| stage.chain_id == chain.id)
        .collect();
    assert!(stages.iter().all(|stage| stage.status == TaskStatus::Completed));
    assert!(stages.iter().any(|stage| {
        stage.name == "DNS Resolution" && stage.provider_id.as_deref() == Some("native_dns")
    }));

    let ip = snapshot
        .assets
        .iter()
        .find(|asset| {
            asset.asset_type == AssetType::IPAddress
                && asset.canonical_identity == "192.0.2.20"
        })
        .expect("DNS Recon should persist the resolved IP");
    assert_eq!(ip.metadata["in_scope"], serde_json::json!(true));

    assert!(snapshot
        .provider_runs
        .iter()
        .any(|run| run.chain_id == chain.id && run.provider_id == "native_dns"));
    assert!(snapshot
        .evidence
        .iter()
        .any(|evidence| evidence.target == "example.test"));
}
