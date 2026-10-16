//! Milestone 6 / Issue #58: the Username OSINT provider wave (Sherlock, Maigret,
//! socialscan), driven entirely offline by `fixtures/fake-*.sh`. No network, no
//! real usernames. Focuses on evidence-first provenance and cross-provider
//! canonical deduplication: multiple providers observing the same public profile
//! produce one canonical asset with one observation per provider run, and nothing
//! silently merges identities.

use macsploit_core::{
    assets::{AssetType, Id, RelationshipType},
    database::Store,
    dns::StaticDnsResolver,
    events::ChainStatus,
    orchestration::{ChainKind, Engine, Snapshot},
    process::ToolConfig,
};
use serde_json::json;
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
        .insert("sherlock".into(), fixture("fake-sherlock.sh"));
    tools
        .overrides
        .insert("maigret".into(), fixture("fake-maigret.sh"));
    tools
        .overrides
        .insert("socialscan".into(), fixture("fake-socialscan.sh"));
    tools
}

fn open(root: &Path, tools: ToolConfig) -> Engine {
    Engine::open_with(
        Store::open(root).unwrap(),
        Duration::ZERO,
        tools,
        Arc::new(StaticDnsResolver::new()),
    )
    .unwrap()
}

fn workspace(engine: &Engine) -> Id {
    engine
        .store
        .create_workspace("OSINT wave", &["example.test".into()])
        .unwrap()
        .id
}

fn wait(engine: &Engine, workspace: Id) -> Snapshot {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !engine.idle() {
        assert!(Instant::now() < deadline, "chain timed out");
        thread::sleep(Duration::from_millis(5));
    }
    engine.store.snapshot(workspace).unwrap()
}

/// Run one username-OSINT chain pinned to `provider` on an already-added target.
fn run_provider(engine: &Engine, ws: Id, target: Id, provider: &str) -> Snapshot {
    engine
        .start(
            ws,
            target,
            ChainKind::UsernameOsint,
            json!({ "provider_id": provider }),
        )
        .unwrap();
    wait(engine, ws)
}

fn account<'a>(snapshot: &'a Snapshot, identity: &str) -> &'a macsploit_core::assets::Asset {
    snapshot
        .assets
        .iter()
        .find(|a| a.asset_type == AssetType::Account && a.canonical_identity == identity)
        .unwrap_or_else(|| panic!("missing Account {identity}"))
}

#[test]
fn each_provider_runs_end_to_end_with_evidence_and_provenance() {
    for (provider, extra_platform) in [
        ("sherlock", None),
        ("maigret", Some("keybase")),
        ("socialscan", None),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let engine = open(temp.path(), tools());
        let ws = workspace(&engine);
        let target = engine.store.add_target(ws, "@octo-synthetic").unwrap();
        let snap = run_provider(&engine, ws, target.id, provider);

        assert_eq!(snap.chains.len(), 1);
        let run = snap.provider_runs.last().expect("a provider run");
        assert_eq!(run.provider_id, provider);

        // Canonical subject + the shared GitHub account.
        let github = account(&snap, "github:octo-synthetic");
        let obs = snap
            .observations
            .iter()
            .find(|o| o.asset_id == github.id)
            .expect("github observation");
        assert!(!obs.discovered_by.is_empty()); // provider display name
        assert_eq!(obs.confidence, "REPORTED");
        let meta = obs.metadata.as_ref().unwrap();
        assert_eq!(meta["provider"], provider); // stable provider id
        assert_eq!(meta["kind"], "osint_account");
        // Uncertainty note travels with the observation.
        assert!(meta["identity_note"]
            .as_str()
            .unwrap()
            .contains("not proof"));

        // A validated profile URL asset linked from the account.
        let url = snap
            .assets
            .iter()
            .find(|a| {
                a.asset_type == AssetType::URL
                    && a.canonical_identity == "https://github.com/octo-synthetic"
            })
            .expect("github profile url asset");
        assert!(snap.relationships.iter().any(|r| {
            r.source_asset_id == github.id
                && r.destination_asset_id == url.id
                && r.relationship_type == RelationshipType::ProfileUrl
        }));

        // Maigret additionally reports a site the others do not.
        if let Some(extra) = extra_platform {
            account(&snap, &format!("{extra}:octo-synthetic"));
        }

        // Evidence is attributable to this provider's run and re-readable.
        assert!(!snap.evidence.is_empty());
        for evidence in &snap.evidence {
            engine.store.read_evidence(ws, evidence.id).unwrap();
        }
        engine.shutdown();
    }
}

#[test]
fn cross_provider_discoveries_dedupe_the_asset_but_keep_per_provider_observations() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("store");
    let ws = {
        let engine = open(&root, tools());
        let ws = workspace(&engine);
        let target = engine.store.add_target(ws, "@octo-synthetic").unwrap();
        // All three providers observe github.com/octo-synthetic.
        run_provider(&engine, ws, target.id, "sherlock");
        run_provider(&engine, ws, target.id, "maigret");
        run_provider(&engine, ws, target.id, "socialscan");
        engine.shutdown();
        ws
    };

    // Restart over the same storage: provenance survives.
    let engine = open(&root, tools());
    let snap = engine.store.snapshot(ws).unwrap();
    assert_eq!(snap.chains.len(), 3);

    // Exactly one canonical GitHub account and one canonical profile URL asset.
    let github_accounts: Vec<_> = snap
        .assets
        .iter()
        .filter(|a| {
            a.asset_type == AssetType::Account && a.canonical_identity == "github:octo-synthetic"
        })
        .collect();
    assert_eq!(github_accounts.len(), 1, "github account deduplicates");
    let github = github_accounts[0];
    let github_urls: Vec<_> = snap
        .assets
        .iter()
        .filter(|a| {
            a.asset_type == AssetType::URL
                && a.canonical_identity == "https://github.com/octo-synthetic"
        })
        .collect();
    assert_eq!(github_urls.len(), 1, "profile URL deduplicates");

    // One observation per provider on the canonical account, each attributed and
    // carrying its own provider/run metadata.
    let mut providers: Vec<String> = snap
        .observations
        .iter()
        .filter(|o| o.asset_id == github.id)
        .map(|o| {
            // Each observation points at a distinct provider run and carries the
            // stable provider id in its metadata (plus the display name).
            assert!(o.provider_run_id.is_some());
            assert!(!o.discovered_by.is_empty());
            o.metadata.as_ref().unwrap()["provider"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    providers.sort();
    assert_eq!(providers, ["maigret", "sherlock", "socialscan"]);

    // Distinct provider runs, and each account observation maps to evidence.
    let run_ids: std::collections::HashSet<_> = snap
        .observations
        .iter()
        .filter(|o| o.asset_id == github.id)
        .map(|o| o.provider_run_id)
        .collect();
    assert_eq!(run_ids.len(), 3, "three distinct provider runs");

    // Keybase (maigret-only) remains its own canonical account — no silent merge.
    account(&snap, "keybase:octo-synthetic");

    // All evidence remains attributable and re-readable after restart.
    let evidence_providers: std::collections::HashSet<_> =
        snap.evidence.iter().map(|e| e.provider.clone()).collect();
    for p in ["sherlock", "maigret", "socialscan"] {
        assert!(
            evidence_providers
                .iter()
                .any(|ep| ep.to_lowercase().contains(p)),
            "evidence from {p} is present"
        );
    }
    for evidence in &snap.evidence {
        engine.store.read_evidence(ws, evidence.id).unwrap();
    }
}

#[test]
fn cancellation_keeps_captured_evidence_without_structured_results() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(temp.path(), tools());
    let ws = workspace(&engine);
    let target = engine.store.add_target(ws, "@slow-synthetic").unwrap();
    let chain = engine
        .start(
            ws,
            target.id,
            ChainKind::UsernameOsint,
            json!({"provider_id": "maigret"}),
        )
        .unwrap();
    // Let the scan start, then cancel it.
    thread::sleep(Duration::from_millis(80));
    engine.cancel(ws, chain.id).unwrap();
    let snap = wait(&engine, ws);
    assert_eq!(snap.chains[0].status, ChainStatus::Cancelled);
    // No account assets (the report is only written on completion); captured
    // process output is still preserved as evidence.
    assert!(!snap
        .assets
        .iter()
        .any(|a| a.asset_type == AssetType::Account));
}

#[test]
fn provider_failure_and_malformed_report_preserve_evidence_without_discoveries() {
    for (subject, provider) in [
        ("@failing-synthetic", "sherlock"),
        ("@malformed-synthetic", "socialscan"),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let engine = open(temp.path(), tools());
        let ws = workspace(&engine);
        let target = engine.store.add_target(ws, subject).unwrap();
        let snap = run_provider(&engine, ws, target.id, provider);
        assert!(matches!(
            snap.chains[0].status,
            ChainStatus::Failed | ChainStatus::Partial
        ));
        assert!(!snap
            .assets
            .iter()
            .any(|a| a.asset_type == AssetType::Account));
        // Whatever was captured is still persisted and re-readable.
        for evidence in &snap.evidence {
            engine.store.read_evidence(ws, evidence.id).unwrap();
        }
    }
}

#[test]
fn provider_compatibility_is_enforced_for_the_new_providers() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(temp.path(), tools());
    let ws = workspace(&engine);
    let email = engine.store.add_target(ws, "person@example.test").unwrap();
    // Username-only providers refuse an email target (socialscan supports Email
    // since Issue #64 and is covered by tests/osint_email.rs).
    for provider in ["sherlock", "maigret"] {
        let err = engine
            .start(
                ws,
                email.id,
                ChainKind::EmailOsint,
                json!({ "provider_id": provider }),
            )
            .map(|_| ())
            .unwrap_err();
        assert_eq!(err.code, "ProviderUnsupported");
    }
    engine
        .start(
            ws,
            email.id,
            ChainKind::EmailOsint,
            json!({ "provider_id": "socialscan" }),
        )
        .unwrap();
    wait(&engine, ws);
}
