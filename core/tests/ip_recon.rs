//! Milestone 1.2 end-to-end coverage for Direct IP Recon (Nmap -> HTTPX from a
//! single explicitly selected in-scope IP), driven entirely offline through fake
//! executables. No network access occurs.

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

fn tools() -> ToolConfig {
    let mut tools = ToolConfig::default();
    tools
        .overrides
        .insert("nmap".into(), fixture("fake-nmap.sh"));
    tools
        .overrides
        .insert("httpx".into(), fixture("fake-httpx.sh"));
    tools
}

fn open(temp: &tempfile::TempDir) -> Engine {
    Engine::open_with(
        Store::open(temp.path()).unwrap(),
        Duration::ZERO,
        tools(),
        Arc::new(StaticDnsResolver::new()),
    )
    .unwrap()
}

fn wait(engine: &Engine, workspace: Id) -> Snapshot {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !engine.idle() {
        assert!(Instant::now() < deadline, "chain timed out");
        thread::sleep(Duration::from_millis(5));
    }
    engine.store.snapshot(workspace).unwrap()
}

/// Shared assertions for a completed single-IP Direct IP Recon run: the fake Nmap
/// reports 22/ssh + 443/https, so exactly one Website (the https service) and one
/// Technology (nginx) are produced, linked back to the selected IP.
fn assert_single_ip_outcome(snapshot: &Snapshot, ip: &str, website: &str) {
    assert_eq!(snapshot.chains[0].name, "IP Recon");
    assert_eq!(snapshot.chains[0].status, ChainStatus::Completed);

    let ips: Vec<_> = snapshot
        .assets
        .iter()
        .filter(|a| a.asset_type == AssetType::IPAddress)
        .map(|a| a.canonical_identity.as_str())
        .collect();
    assert_eq!(ips, vec![ip], "only the selected IP is present");
    assert_eq!(
        snapshot
            .assets
            .iter()
            .filter(|a| a.asset_type == AssetType::Port)
            .count(),
        2
    );
    assert_eq!(
        snapshot
            .assets
            .iter()
            .filter(|a| a.asset_type == AssetType::Service)
            .count(),
        2
    );
    assert!(snapshot
        .assets
        .iter()
        .any(|a| a.asset_type == AssetType::Website && a.canonical_identity == website));
    assert!(snapshot
        .assets
        .iter()
        .any(|a| a.asset_type == AssetType::Technology));

    // Two provider runs (nmap, httpx), each with hash-verified evidence.
    assert_eq!(snapshot.provider_runs.len(), 2);
    assert!(snapshot
        .provider_runs
        .iter()
        .any(|r| r.provider_id == "nmap"));
    assert!(snapshot
        .provider_runs
        .iter()
        .any(|r| r.provider_id == "httpx"));
    assert_eq!(snapshot.evidence.len(), 2);

    // Relationships: 2 exposes (IP->Port) + 2 serves (Port->Service) + 1 has_endpoint
    // (IP->Website) + 1 uses_technology (Website->Technology).
    let count = |t: RelationshipType| {
        snapshot
            .relationships
            .iter()
            .filter(|r| r.relationship_type == t)
            .count()
    };
    assert_eq!(count(RelationshipType::Exposes), 2);
    assert_eq!(count(RelationshipType::Serves), 2);
    assert_eq!(count(RelationshipType::HasEndpoint), 1);
    assert_eq!(count(RelationshipType::UsesTechnology), 1);
}

#[test]
fn ip_recon_runs_nmap_then_httpx_for_an_ipv4_target() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(&temp);
    let workspace = engine
        .store
        .create_workspace("Direct IP", &["192.0.2.10".into()])
        .unwrap();
    let target = engine.store.add_target(workspace.id, "192.0.2.10").unwrap();
    assert_eq!(
        target.target_type,
        macsploit_core::targets::TargetType::IPAddress
    );

    engine
        .start(
            workspace.id,
            target.id,
            ChainKind::IpRecon,
            serde_json::Value::Null,
        )
        .unwrap();
    let snapshot = wait(&engine, workspace.id);
    assert_single_ip_outcome(&snapshot, "192.0.2.10", "https://192.0.2.10/");

    // Evidence provenance: at least one Nmap and one HTTPX evidence record, each
    // readable and hash-verified by the store.
    for ev in &snapshot.evidence {
        assert!(engine
            .store
            .read_evidence(workspace.id, ev.id)
            .unwrap()
            .contains("\"provider\""));
    }

    // Persistence across a database reopen.
    drop(engine);
    let reopened = open(&temp);
    let after = reopened.store.snapshot(workspace.id).unwrap();
    assert_eq!(after.chains[0].status, ChainStatus::Completed);
    assert_eq!(after.provider_runs.len(), 2);
    assert_eq!(after.evidence.len(), 2);
    assert!(after.assets.iter().any(
        |a| a.asset_type == AssetType::Website && a.canonical_identity == "https://192.0.2.10/"
    ));
}

#[test]
fn ip_recon_runs_for_an_ipv6_target_with_bracketed_probe_urls() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(&temp);
    let workspace = engine
        .store
        .create_workspace("Direct IPv6", &["2001:db8::10".into()])
        .unwrap();
    let target = engine
        .store
        .add_target(workspace.id, "2001:db8::10")
        .unwrap();

    engine
        .start(
            workspace.id,
            target.id,
            ChainKind::IpRecon,
            serde_json::Value::Null,
        )
        .unwrap();
    let snapshot = wait(&engine, workspace.id);
    // The IPv6 Website identity is a valid bracketed URL (443 normalized away).
    assert_single_ip_outcome(&snapshot, "2001:db8::10", "https://[2001:db8::10]/");
}

#[test]
fn ip_recon_only_scans_the_selected_ip_not_unrelated_workspace_ips() {
    // A second, in-scope IP asset exists in the workspace but is not the chain target
    // and is not discovered by this chain, so Nmap must never scan it.
    let temp = tempfile::tempdir().unwrap();
    let engine = open(&temp);
    let workspace = engine
        .store
        .create_workspace("Isolation", &["192.0.2.10".into(), "192.0.2.99".into()])
        .unwrap();
    let selected = engine.store.add_target(workspace.id, "192.0.2.10").unwrap();
    let _unrelated = engine.store.add_target(workspace.id, "192.0.2.99").unwrap();

    engine
        .start(
            workspace.id,
            selected.id,
            ChainKind::IpRecon,
            serde_json::Value::Null,
        )
        .unwrap();
    let snapshot = wait(&engine, workspace.id);
    assert_eq!(snapshot.chains[0].status, ChainStatus::Completed);

    // The unrelated IP exists as a target-seeded asset but has no discovered ports.
    assert!(
        !snapshot
            .assets
            .iter()
            .any(|a| a.asset_type == AssetType::Port
                && a.canonical_identity.starts_with("192.0.2.99"))
    );
    // Only the selected IP produced ports.
    assert!(
        snapshot
            .assets
            .iter()
            .all(|a| a.asset_type != AssetType::Port
                || a.canonical_identity.starts_with("192.0.2.10"))
    );
}

#[test]
fn ip_recon_rejects_non_ip_targets() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(&temp);
    let workspace = engine
        .store
        .create_workspace(
            "Types",
            &["example.test".into(), "host".into(), "192.0.2.0/24".into()],
        )
        .unwrap();
    for value in [
        "example.test",          // Domain
        "host",                  // Hostname
        "https://example.test/", // URL
        "192.0.2.0/24",          // CIDR
    ] {
        let target = engine.store.add_target(workspace.id, value).unwrap();
        let error = engine
            .start(
                workspace.id,
                target.id,
                ChainKind::IpRecon,
                serde_json::Value::Null,
            )
            .unwrap_err();
        assert_eq!(
            error.code, "InvalidTarget",
            "value {value} should be rejected"
        );
    }
}

#[test]
fn ip_recon_authorizes_against_workspace_scope() {
    let temp = tempfile::tempdir().unwrap();

    // Exact IPv4 scope -> allowed.
    {
        let engine = open(&temp);
        let ws = engine
            .store
            .create_workspace("Exact", &["192.168.1.50".into()])
            .unwrap();
        let t = engine.store.add_target(ws.id, "192.168.1.50").unwrap();
        assert!(engine
            .start(ws.id, t.id, ChainKind::IpRecon, serde_json::Value::Null)
            .is_ok());
        wait(&engine, ws.id);
    }
    // CIDR scope containing the IP -> allowed; a different CIDR -> denied.
    {
        let temp2 = tempfile::tempdir().unwrap();
        let engine = open(&temp2);
        let ws = engine
            .store
            .create_workspace("Cidr", &["192.168.1.0/24".into()])
            .unwrap();
        let t = engine.store.add_target(ws.id, "192.168.1.50").unwrap();
        assert!(engine
            .start(ws.id, t.id, ChainKind::IpRecon, serde_json::Value::Null)
            .is_ok());
        wait(&engine, ws.id);
    }
    {
        let temp3 = tempfile::tempdir().unwrap();
        let engine = open(&temp3);
        let ws = engine
            .store
            .create_workspace("CidrDeny", &["192.168.2.0/24".into()])
            .unwrap();
        let t = engine.store.add_target(ws.id, "192.168.1.50").unwrap();
        assert_eq!(
            engine
                .start(ws.id, t.id, ChainKind::IpRecon, serde_json::Value::Null)
                .unwrap_err()
                .code,
            "ScopeViolation"
        );
    }
    // Out-of-family scope (a domain) never authorizes an IP target.
    {
        let temp4 = tempfile::tempdir().unwrap();
        let engine = open(&temp4);
        let ws = engine
            .store
            .create_workspace("DomainScope", &["example.test".into()])
            .unwrap();
        let t = engine.store.add_target(ws.id, "192.168.1.50").unwrap();
        assert_eq!(
            engine
                .start(ws.id, t.id, ChainKind::IpRecon, serde_json::Value::Null)
                .unwrap_err()
                .code,
            "ScopeViolation"
        );
    }
    // Exact IPv6 scope -> allowed.
    {
        let temp5 = tempfile::tempdir().unwrap();
        let engine = open(&temp5);
        let ws = engine
            .store
            .create_workspace("V6", &["::1".into()])
            .unwrap();
        let t = engine.store.add_target(ws.id, "::1").unwrap();
        assert!(engine
            .start(ws.id, t.id, ChainKind::IpRecon, serde_json::Value::Null)
            .is_ok());
        wait(&engine, ws.id);
    }
    // IPv6 CIDR scope containing the address -> allowed.
    {
        let temp6 = tempfile::tempdir().unwrap();
        let engine = open(&temp6);
        let ws = engine
            .store
            .create_workspace("V6Cidr", &["2001:db8::/32".into()])
            .unwrap();
        let t = engine.store.add_target(ws.id, "2001:db8::10").unwrap();
        assert!(engine
            .start(ws.id, t.id, ChainKind::IpRecon, serde_json::Value::Null)
            .is_ok());
        wait(&engine, ws.id);
    }
}
