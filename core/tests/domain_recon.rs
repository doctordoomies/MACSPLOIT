//! Phase 1A/1B end-to-end coverage for the real Domain Recon chain (Subfinder +
//! native DNS), driven entirely offline through a fake executable and a static
//! DNS resolver. No network access occurs.

use macsploit_core::{
    assets::{AssetType, Id, RelationshipType},
    database::Store,
    dns::{DnsResolver, StaticDnsResolver},
    events::{ChainStatus, TaskStatus},
    orchestration::{ChainKind, Engine, Snapshot},
    process::ToolConfig,
};
use std::{
    net::Ipv4Addr,
    path::PathBuf,
    sync::Arc,
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

fn ip(v: &str) -> Ipv4Addr {
    v.parse().unwrap()
}

fn fake_resolver() -> Arc<dyn DnsResolver> {
    Arc::new(
        StaticDnsResolver::new()
            .with("api.example.test", &[ip("192.0.2.10")], &[])
            .with("dev.example.test", &[ip("192.0.2.11")], &[])
            .with("auth.example.test", &[ip("192.0.2.12")], &[]),
    )
}

fn engine_with(tools: ToolConfig, resolver: Arc<dyn DnsResolver>) -> (tempfile::TempDir, Engine, Id, Id) {
    let temp = tempfile::tempdir().unwrap();
    let engine =
        Engine::open_with(Store::open(temp.path()).unwrap(), Duration::ZERO, tools, resolver).unwrap();
    let workspace = engine
        .store
        .create_workspace(
            "Domain Assessment",
            &[
                "example.test".into(),
                "*.example.test".into(),
                "192.0.2.0/24".into(),
            ],
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
fn domain_recon_resolves_subdomains_end_to_end_and_persists() {
    let (temp, engine, workspace, target) =
        engine_with(tools_with_subfinder(fake_subfinder()), fake_resolver());
    let chain = engine
        .start(workspace, target, ChainKind::DomainRecon)
        .unwrap();
    let snapshot = wait(&engine, workspace);

    // Chain shape now includes a DNS Resolution stage pinned to native_dns.
    assert_eq!(snapshot.chains[0].id, chain.id);
    assert_eq!(snapshot.chains[0].name, "Domain Recon");
    assert_eq!(snapshot.chains[0].status, ChainStatus::Completed);
    assert!(snapshot.stages.iter().all(|s| s.status == TaskStatus::Completed));
    assert!(snapshot
        .stages
        .iter()
        .any(|s| s.name == "DNS Resolution" && s.provider_id.as_deref() == Some("native_dns")));

    // Assets: apex domain + 3 subdomains + 3 IP addresses.
    let subdomains = snapshot
        .assets
        .iter()
        .filter(|a| a.asset_type == AssetType::Subdomain)
        .count();
    let ips: Vec<_> = snapshot
        .assets
        .iter()
        .filter(|a| a.asset_type == AssetType::IPAddress)
        .map(|a| a.canonical_identity.as_str())
        .collect();
    assert_eq!(subdomains, 3);
    assert_eq!(ips.len(), 3, "got {ips:?}");
    for expected in ["192.0.2.10", "192.0.2.11", "192.0.2.12"] {
        assert!(ips.contains(&expected), "missing {expected}");
    }
    // IP assets are in scope (192.0.2.0/24) and attributed to native DNS.
    for asset in snapshot
        .assets
        .iter()
        .filter(|a| a.asset_type == AssetType::IPAddress)
    {
        assert_eq!(asset.metadata["in_scope"], serde_json::json!(true));
        assert_eq!(asset.metadata["tool"], serde_json::json!("native_dns"));
        assert_eq!(asset.metadata["record_type"], serde_json::json!("A"));
    }

    // Relationships: 3 has_subdomain + 3 resolves_to.
    let has_sub = snapshot
        .relationships
        .iter()
        .filter(|r| r.relationship_type == RelationshipType::HasSubdomain)
        .count();
    let resolves = snapshot
        .relationships
        .iter()
        .filter(|r| r.relationship_type == RelationshipType::ResolvesTo)
        .count();
    assert_eq!(has_sub, 3);
    assert_eq!(resolves, 3);

    // Two provider runs: subfinder then native_dns, both completed.
    assert_eq!(snapshot.provider_runs.len(), 2);
    let dns_run = snapshot
        .provider_runs
        .iter()
        .find(|r| r.provider_id == "native_dns")
        .expect("native_dns run");
    assert_eq!(dns_run.status, TaskStatus::Completed);
    assert!(dns_run.provider_version.starts_with("core "));
    assert!(dns_run.raw_output_reference.is_some());

    // Evidence: subfinder envelope + DNS envelope, both hash-verifiable.
    assert_eq!(snapshot.evidence.len(), 2);
    let dns_evidence = snapshot
        .evidence
        .iter()
        .find(|e| e.provider == "Native DNS Resolver")
        .expect("dns evidence");
    let raw = engine.store.read_evidence(workspace, dns_evidence.id).unwrap();
    let envelope: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(envelope["provider"], "native_dns");
    assert!(envelope["stdout"].as_str().unwrap().contains("192.0.2.10"));

    // resolves_to provenance is attributed to the DNS run.
    let ip_asset = snapshot
        .assets
        .iter()
        .find(|a| a.canonical_identity == "192.0.2.10")
        .unwrap();
    assert!(snapshot
        .observations
        .iter()
        .any(|o| o.asset_id == ip_asset.id
            && o.discovered_by == "Native DNS Resolver"
            && o.provider_run_id == Some(dns_run.id)));

    // Persistence across a database reopen.
    drop(engine);
    let reopened = Engine::open_with(
        Store::open(temp.path()).unwrap(),
        Duration::ZERO,
        ToolConfig::default(),
        Arc::new(StaticDnsResolver::new()),
    )
    .unwrap();
    let after = reopened.store.snapshot(workspace).unwrap();
    assert_eq!(after.assets.len(), snapshot.assets.len());
    assert_eq!(after.relationships.len(), snapshot.relationships.len());
    assert_eq!(after.provider_runs.len(), 2);
    assert_eq!(after.evidence.len(), 2);
    assert_eq!(after.chains[0].status, ChainStatus::Completed);
}

#[test]
fn domain_recon_handles_many_to_many_and_partial_dns() {
    // api and auth share an IP; dev has A+AAAA; missing has no records.
    let resolver: Arc<dyn DnsResolver> = Arc::new(
        StaticDnsResolver::new()
            .with("api.example.test", &[ip("192.0.2.20")], &[])
            .with("auth.example.test", &[ip("192.0.2.20")], &[])
            .with(
                "dev.example.test",
                &[ip("192.0.2.11")],
                &["2001:db8::11".parse().unwrap()],
            ),
    );
    let (_temp, engine, workspace, target) =
        engine_with(tools_with_subfinder(fake_subfinder()), resolver);
    engine
        .start(workspace, target, ChainKind::DomainRecon)
        .unwrap();
    let snapshot = wait(&engine, workspace);
    assert_eq!(snapshot.chains[0].status, ChainStatus::Completed);

    // Shared IP is one asset; api/auth both resolve_to it (many-to-many).
    let shared = snapshot
        .assets
        .iter()
        .filter(|a| a.canonical_identity == "192.0.2.20")
        .count();
    assert_eq!(shared, 1);
    // dev contributes an IPv4 and an IPv6 asset.
    assert!(snapshot
        .assets
        .iter()
        .any(|a| a.canonical_identity == "2001:db8::11"));
    // Total resolves_to = api, auth, dev(A), dev(AAAA) = 4; auth's subfinder host
    // is present so has_subdomain covers api/dev/auth = 3.
    let resolves = snapshot
        .relationships
        .iter()
        .filter(|r| r.relationship_type == RelationshipType::ResolvesTo)
        .count();
    assert_eq!(resolves, 4);
}

#[test]
fn domain_recon_fails_cleanly_when_subfinder_is_missing() {
    let (_temp, engine, workspace, target) = engine_with(
        tools_with_subfinder(PathBuf::from("/nonexistent/subfinder")),
        fake_resolver(),
    );
    engine
        .start(workspace, target, ChainKind::DomainRecon)
        .unwrap();
    let snapshot = wait(&engine, workspace);
    let chain = &snapshot.chains[0];
    assert_eq!(chain.status, ChainStatus::Failed);
    assert_eq!(chain.error_code.as_deref(), Some("ProviderMissing"));
    assert!(snapshot
        .assets
        .iter()
        .all(|a| a.asset_type != AssetType::Subdomain && a.asset_type != AssetType::IPAddress));
    assert!(snapshot.evidence.is_empty());
}

#[test]
fn domain_recon_requires_target_in_scope() {
    let (_temp, engine, workspace, _target) =
        engine_with(tools_with_subfinder(fake_subfinder()), fake_resolver());
    let outside = engine.store.add_target(workspace, "other.test").unwrap();
    let error = engine
        .start(workspace, outside.id, ChainKind::DomainRecon)
        .unwrap_err();
    assert_eq!(error.code, "ScopeViolation");
}
