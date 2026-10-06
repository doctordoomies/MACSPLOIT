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
        .start(
            workspace.id,
            target.id,
            ChainKind::DnsRecon,
            serde_json::Value::Null,
        )
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
    assert!(stages
        .iter()
        .all(|stage| stage.status == TaskStatus::Completed));
    assert!(stages.iter().any(|stage| {
        stage.name == "DNS Resolution" && stage.provider_id.as_deref() == Some("native_dns")
    }));

    let ip = snapshot
        .assets
        .iter()
        .find(|asset| {
            asset.asset_type == AssetType::IPAddress && asset.canonical_identity == "192.0.2.20"
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

#[test]
fn dns_recon_reverse_lookup_for_url_ip_target() {
    // Owner case: scope authorizes 127.0.0.1, target is the URL http://127.0.0.1/.
    // DNS Recon must accept the URL, extract the IP host, and do a reverse (PTR) lookup.
    let temp = tempfile::tempdir().unwrap();
    let loopback: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let resolver = StaticDnsResolver::new().with_ptr(loopback, &["localhost"]);
    let engine = Engine::open_with(
        Store::open(temp.path()).unwrap(),
        Duration::ZERO,
        ToolConfig::default(),
        Arc::new(resolver),
    )
    .unwrap();
    let workspace = engine
        .store
        .create_workspace("Reverse DNS", &["127.0.0.1".into()])
        .unwrap();
    let target = engine
        .store
        .add_target(workspace.id, "http://127.0.0.1/")
        .unwrap();
    assert_eq!(target.target_type, macsploit_core::targets::TargetType::URL);

    let chain = engine
        .start(
            workspace.id,
            target.id,
            ChainKind::DnsRecon,
            serde_json::Value::Null,
        )
        .unwrap();
    let snapshot = wait(&engine, workspace.id);
    assert_eq!(
        snapshot
            .chains
            .iter()
            .find(|c| c.id == chain.id)
            .unwrap()
            .status,
        ChainStatus::Completed
    );

    // The looked-up IP exists as an asset and the PTR name is a linked Hostname.
    assert!(snapshot
        .assets
        .iter()
        .any(|a| a.asset_type == AssetType::IPAddress && a.canonical_identity == "127.0.0.1"));
    let ptr = snapshot
        .assets
        .iter()
        .find(|a| a.asset_type == AssetType::Hostname && a.canonical_identity == "localhost")
        .expect("PTR hostname asset");
    // Relationship is a PTR record (not a forward resolves_to).
    assert!(snapshot
        .relationships
        .iter()
        .any(|r| r.destination_asset_id == ptr.id
            && r.relationship_type == macsploit_core::assets::RelationshipType::PtrRecord));
    assert!(snapshot
        .provider_runs
        .iter()
        .any(|r| r.provider_id == "native_dns"));
    assert!(!snapshot.evidence.is_empty());
}

#[test]
fn dns_recon_reverse_lookup_for_bare_ip_and_rejects_cidr() {
    let temp = tempfile::tempdir().unwrap();
    let ip: std::net::IpAddr = "192.0.2.10".parse().unwrap();
    let resolver = StaticDnsResolver::new().with_ptr(ip, &["host.example.test"]);
    let engine = Engine::open_with(
        Store::open(temp.path()).unwrap(),
        Duration::ZERO,
        ToolConfig::default(),
        Arc::new(resolver),
    )
    .unwrap();
    let workspace = engine
        .store
        .create_workspace("Rev", &["192.0.2.0/24".into()])
        .unwrap();
    // Bare IP target → reverse PTR.
    let ip_target = engine.store.add_target(workspace.id, "192.0.2.10").unwrap();
    engine
        .start(
            workspace.id,
            ip_target.id,
            ChainKind::DnsRecon,
            serde_json::Value::Null,
        )
        .unwrap();
    let snapshot = wait(&engine, workspace.id);
    assert!(snapshot.assets.iter().any(
        |a| a.asset_type == AssetType::Hostname && a.canonical_identity == "host.example.test"
    ));

    // A CIDR target is not a valid DNS Recon target.
    let cidr = engine
        .store
        .add_target(workspace.id, "192.0.2.0/24")
        .unwrap();
    let err = engine
        .start(
            workspace.id,
            cidr.id,
            ChainKind::DnsRecon,
            serde_json::Value::Null,
        )
        .unwrap_err();
    assert_eq!(err.code, "InvalidTarget");
}

#[test]
fn dns_targets_extract_hosts_preserve_scope_and_evidence_offline() {
    for (target_value, scope, reverse) in [
        ("localhost", "localhost", false),
        (
            "http://localhost:3000/path?fixture=private#fragment",
            "localhost",
            false,
        ),
        ("127.0.0.1", "127.0.0.1", true),
        ("http://127.0.0.1/", "127.0.0.1", true),
        ("::1", "::1", true),
        ("http://[::1]:3000/path", "::1", true),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let resolver = StaticDnsResolver::new()
            .with("localhost", &["127.0.0.1".parse().unwrap()], &[])
            .with_ptr("127.0.0.1".parse().unwrap(), &["localhost"])
            .with_ptr("::1".parse().unwrap(), &["localhost"]);
        let engine = Engine::open_with(
            Store::open(temp.path()).unwrap(),
            Duration::ZERO,
            ToolConfig::default(),
            Arc::new(resolver),
        )
        .unwrap();
        let ws = engine.store.create_workspace("DNS cases", &[]).unwrap();
        let target = engine.store.add_target(ws.id, target_value).unwrap();
        assert_eq!(
            engine
                .start(
                    ws.id,
                    target.id,
                    ChainKind::DnsRecon,
                    serde_json::Value::Null
                )
                .unwrap_err()
                .code,
            "ScopeViolation"
        );
        engine
            .store
            .update_workspace_scope(ws.id, &[scope.into()])
            .unwrap();
        engine
            .start(
                ws.id,
                target.id,
                ChainKind::DnsRecon,
                serde_json::Value::Null,
            )
            .unwrap();
        let snapshot = wait(&engine, ws.id);
        assert_eq!(
            snapshot.chains[0].status,
            ChainStatus::Completed,
            "{target_value}"
        );
        let relation = if reverse {
            macsploit_core::assets::RelationshipType::PtrRecord
        } else {
            macsploit_core::assets::RelationshipType::ResolvesTo
        };
        assert!(
            snapshot
                .relationships
                .iter()
                .any(|r| r.relationship_type == relation),
            "{target_value}"
        );
        let evidence = &snapshot.evidence[0];
        assert_eq!(evidence.target, target.normalized_value);
        assert!(snapshot
            .observations
            .iter()
            .any(|o| o.evidence_id == Some(evidence.id)));
        let envelope: serde_json::Value = serde_json::from_slice(
            &std::fs::read(engine.store.directory(ws.id).join(&evidence.relative_path)).unwrap(),
        )
        .unwrap();
        let report: serde_json::Value =
            serde_json::from_str(envelope["stdout"].as_str().unwrap()).unwrap();
        assert_eq!(
            report[if reverse { "reverse" } else { "records" }]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(report[if reverse { "records" } else { "reverse" }]
            .as_array()
            .unwrap()
            .is_empty());
    }
}

#[test]
fn ptr_empty_and_failure_outcomes_are_evidence_not_invented_hostnames() {
    use macsploit_core::dns::DnsOutcome;
    for outcome in [
        DnsOutcome::NoRecords,
        DnsOutcome::NxDomain,
        DnsOutcome::Timeout,
        DnsOutcome::TemporaryFailure,
        DnsOutcome::ResolverFailure,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let resolver =
            StaticDnsResolver::new().with_ptr_outcome("127.0.0.1".parse().unwrap(), outcome);
        let engine = Engine::open_with(
            Store::open(temp.path()).unwrap(),
            Duration::ZERO,
            ToolConfig::default(),
            Arc::new(resolver),
        )
        .unwrap();
        let ws = engine
            .store
            .create_workspace("PTR outcome", &["127.0.0.1".into()])
            .unwrap();
        let target = engine.store.add_target(ws.id, "http://127.0.0.1/").unwrap();
        engine
            .start(
                ws.id,
                target.id,
                ChainKind::DnsRecon,
                serde_json::Value::Null,
            )
            .unwrap();
        let snapshot = wait(&engine, ws.id);
        assert!(!snapshot
            .assets
            .iter()
            .any(|a| a.asset_type == AssetType::Hostname));
        assert!(snapshot.relationships.is_empty());
        let evidence = &snapshot.evidence[0];
        let envelope: serde_json::Value = serde_json::from_slice(
            &std::fs::read(engine.store.directory(ws.id).join(&evidence.relative_path)).unwrap(),
        )
        .unwrap();
        let report: serde_json::Value =
            serde_json::from_str(envelope["stdout"].as_str().unwrap()).unwrap();
        assert_eq!(
            report["reverse"][0]["outcome"],
            serde_json::to_value(outcome).unwrap()
        );
    }
}
