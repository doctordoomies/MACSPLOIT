//! Milestone 6.2 / Issue #64: Email OSINT across providers (user-scanner +
//! socialscan), driven entirely offline by `fixtures/fake-*.sh`. No network, no real
//! email addresses. Verifies per-provider provenance, cross-provider canonical
//! deduplication, failure semantics, and restart persistence. Holehe is deliberately
//! not integrated (see docs/osint.md).

use macsploit_core::{
    assets::{AssetType, Id},
    database::Store,
    dns::StaticDnsResolver,
    events::{ChainStatus, TaskStatus},
    orchestration::{ChainKind, Engine, Snapshot},
    process::ToolConfig,
    providers::ProviderRegistry,
};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
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
        .insert("user-scanner".into(), fixture("fake-user-scanner.sh"));
    tools
        .overrides
        .insert("socialscan".into(), fixture("fake-socialscan.sh"));
    tools
}

fn open(root: &Path) -> Engine {
    Engine::open_with(
        Store::open(root).unwrap(),
        Duration::ZERO,
        tools(),
        Arc::new(StaticDnsResolver::new()),
    )
    .unwrap()
}

fn wait(engine: &Engine, ws: Id) -> Snapshot {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !engine.idle() {
        assert!(Instant::now() < deadline, "chain timed out");
        thread::sleep(Duration::from_millis(5));
    }
    engine.store.snapshot(ws).unwrap()
}

fn run(engine: &Engine, ws: Id, target: Id, provider: &str) -> Snapshot {
    engine
        .start(
            ws,
            target,
            ChainKind::EmailOsint,
            json!({ "provider_id": provider }),
        )
        .unwrap();
    wait(engine, ws)
}

#[test]
fn socialscan_is_offered_for_email_osint() {
    let registry = ProviderRegistry::default();
    let status = registry
        .status(&tools())
        .into_iter()
        .find(|s| s.metadata.id == "socialscan")
        .unwrap();
    let value = serde_json::to_value(&status).unwrap();
    assert_eq!(value["installation"]["state"], "INSTALLED");
    assert_eq!(value["installation"]["version"], "2.0.1");
    assert!(value["capabilities"]
        .as_array()
        .unwrap()
        .contains(&json!("EMAIL_OSINT")));
    assert!(value["supported_target_types"]
        .as_array()
        .unwrap()
        .contains(&json!("EmailAddress")));
}

#[test]
fn email_providers_dedup_canonically_keep_provenance_and_survive_restart() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("store");
    let ws = {
        let engine = open(&root);
        let ws = engine
            .store
            .create_workspace("Email OSINT", &["example.test".into()])
            .unwrap()
            .id;
        let target = engine
            .store
            .add_target(ws, "researcher@example.test")
            .unwrap();
        let first = run(&engine, ws, target.id, "user_scanner");
        assert_eq!(first.chains[0].status, ChainStatus::Completed);
        let second = run(&engine, ws, target.id, "socialscan");
        let social = second.chains.last().unwrap();
        // socialscan's failed GitHub lookup makes the run partial, not failed.
        assert_eq!(social.status, ChainStatus::Partial);
        engine.shutdown();
        ws
    };
    let engine = open(&root);
    let snap = engine.store.snapshot(ws).unwrap();
    // Canonical dedup never implies a correlation between distinct identities.
    assert!(snap.correlations.is_empty());

    // One canonical subject and one canonical Pinterest account, reported by both.
    let subjects: Vec<_> = snap
        .assets
        .iter()
        .filter(|a| a.asset_type == AssetType::EmailAddress)
        .collect();
    assert_eq!(subjects.len(), 1);
    let pinterest: Vec<_> = snap
        .assets
        .iter()
        .filter(|a| a.canonical_identity == "pinterest:researcher@example.test")
        .collect();
    assert_eq!(pinterest.len(), 1, "cross-provider canonical deduplication");
    let obs: Vec<_> = snap
        .observations
        .iter()
        .filter(|o| o.asset_id == pinterest[0].id)
        .collect();
    let mut providers: Vec<&str> = obs.iter().map(|o| o.discovered_by.as_str()).collect();
    providers.sort();
    assert_eq!(providers, ["socialscan", "user-scanner"]);
    assert!(obs.iter().all(|o| o.confidence == "REPORTED"));
    // Each provider observation links to that provider run's own evidence.
    for o in &obs {
        let run = snap
            .provider_runs
            .iter()
            .find(|r| Some(r.id) == o.provider_run_id)
            .unwrap();
        let ev = o.evidence_id.unwrap();
        assert!(snap
            .evidence
            .iter()
            .any(|e| e.id == ev && e.provider_run_id == run.id));
        engine.store.read_evidence(ws, ev).unwrap();
    }
    let social_obs = obs
        .iter()
        .find(|o| o.discovered_by == "socialscan")
        .unwrap();
    assert_eq!(
        social_obs.metadata.as_ref().unwrap()["upstream_status"],
        "registered"
    );

    // Each run keeps its own subject summary; socialscan's failure is an error.
    let summaries: Vec<&Value> = snap
        .observations
        .iter()
        .filter(|o| o.asset_id == subjects[0].id)
        .filter_map(|o| o.metadata.as_ref())
        .collect();
    assert_eq!(summaries.len(), 2);
    let social_summary = summaries
        .iter()
        .find(|m| m["provider"] == "socialscan")
        .unwrap();
    assert_eq!(social_summary["counts"]["error"], 1);
    assert_eq!(social_summary["counts"]["negative"], 1);
    assert!(social_summary["identity_note"]
        .as_str()
        .unwrap()
        .contains("not proof"));
}

#[test]
fn email_runs_reject_username_targets_and_report_failures_with_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(temp.path());
    let ws = engine
        .store
        .create_workspace("Email OSINT", &[])
        .unwrap()
        .id;
    let user = engine.store.add_target(ws, "@octo-synthetic").unwrap();
    assert_eq!(
        engine
            .start(
                ws,
                user.id,
                ChainKind::EmailOsint,
                json!({"provider_id": "socialscan"})
            )
            .unwrap_err()
            .code,
        "InvalidTarget"
    );
    // Zero results: an unknown email yields an empty report — completed, no accounts.
    let quiet = engine.store.add_target(ws, "nobody@example.test").unwrap();
    let snap = run(&engine, ws, quiet.id, "socialscan");
    assert_eq!(snap.chains[0].status, ChainStatus::Completed);
    assert!(!snap
        .assets
        .iter()
        .any(|a| a.asset_type == AssetType::Account));
    assert_eq!(snap.provider_runs[0].status, TaskStatus::Completed);
}
