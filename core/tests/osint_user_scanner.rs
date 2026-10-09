//! Milestone 6 / Issue #22: Username + Email OSINT through user-scanner, driven
//! entirely offline by `fixtures/fake-user-scanner.sh`. No network, no real
//! usernames or emails.

use macsploit_core::{
    assets::{AssetType, Id, RelationshipType},
    database::Store,
    dns::StaticDnsResolver,
    events::{ChainStatus, EventType, TaskStatus},
    orchestration::{ChainKind, Engine, Snapshot},
    process::{Installation, ToolConfig},
    providers::{Capability, Provider, ProviderContext, ProviderRegistry, UserScannerProvider},
};
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{atomic::AtomicBool, Arc},
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

/// A workspace whose host scope deliberately does NOT cover any OSINT platform.
fn workspace(engine: &Engine) -> Id {
    engine
        .store
        .create_workspace("OSINT", &["example.test".into()])
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

fn run(engine: &Engine, workspace: Id, target: &str, kind: ChainKind) -> Snapshot {
    let target = engine.store.add_target(workspace, target).unwrap();
    engine
        .start(workspace, target.id, kind, Value::Null)
        .unwrap();
    wait(engine, workspace)
}

fn asset<'a>(
    snapshot: &'a Snapshot,
    kind: AssetType,
    identity: &str,
) -> &'a macsploit_core::assets::Asset {
    snapshot
        .assets
        .iter()
        .find(|a| a.asset_type == kind && a.canonical_identity == identity)
        .unwrap_or_else(|| panic!("missing {kind:?} {identity}"))
}

#[test]
fn provider_center_reports_version_unsupported_and_missing() {
    let registry = ProviderRegistry::default();
    let status = |tools: &ToolConfig| {
        registry
            .status(tools)
            .into_iter()
            .find(|s| s.metadata.id == "user_scanner")
            .unwrap()
    };
    let installed = status(&tools());
    assert_eq!(
        installed.installation,
        Installation::Installed {
            version: "1.5.2.1".into(),
            path: Some(fixture("fake-user-scanner.sh")),
        }
    );
    assert_eq!(
        installed.metadata.capabilities,
        vec![Capability::UsernameOsint, Capability::EmailOsint]
    );

    let temp = tempfile::tempdir().unwrap();
    let newer = temp.path().join("user-scanner");
    fs::write(
        &newer,
        "#!/bin/sh\necho 'user-scanner current version -> 2.0.0'\n",
    )
    .unwrap();
    fs::set_permissions(&newer, fs::Permissions::from_mode(0o755)).unwrap();
    let mut config = ToolConfig::default();
    config.overrides.insert("user-scanner".into(), newer);
    assert_eq!(
        status(&config).installation,
        Installation::UnsupportedVersion {
            version: "2.0.0".into()
        }
    );

    let mut missing = ToolConfig::default();
    missing
        .overrides
        .insert("user-scanner".into(), temp.path().join("absent"));
    assert_eq!(status(&missing).installation, Installation::Missing);
}

#[test]
fn adding_osint_targets_never_launches_a_run() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(temp.path(), tools());
    let ws = workspace(&engine);
    engine.store.add_target(ws, "@octo-synthetic").unwrap();
    engine
        .store
        .add_target(ws, "researcher@example.test")
        .unwrap();
    thread::sleep(Duration::from_millis(50));
    let snapshot = engine.store.snapshot(ws).unwrap();
    assert!(snapshot.chains.is_empty() && snapshot.provider_runs.is_empty());
}

#[test]
fn username_osint_end_to_end_with_evidence_provenance_and_uncertainty() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(temp.path(), tools());
    let ws = workspace(&engine);
    let snapshot = run(&engine, ws, "@octo-synthetic", ChainKind::UsernameOsint);

    let chain = &snapshot.chains[0];
    assert_eq!(chain.name, "Username OSINT");
    // An upstream Error record makes the run PARTIAL, not COMPLETED or FAILED.
    assert_eq!(chain.status, ChainStatus::Partial);
    let run = &snapshot.provider_runs[0];
    assert_eq!(run.provider_id, "user_scanner");
    assert_eq!(run.provider_version, "1.5.2.1");
    assert_eq!(run.status, TaskStatus::Completed);
    assert_eq!(
        snapshot
            .stages
            .iter()
            .find(|s| s.capability.is_some())
            .unwrap()
            .provider_id
            .as_deref(),
        Some("user_scanner")
    );

    // Canonical graph: subject, three positive accounts (duplicate Github collapsed),
    // two validated profile URLs (javascript: URL rejected).
    let subject = asset(&snapshot, AssetType::Username, "@octo-synthetic");
    let github = asset(&snapshot, AssetType::Account, "github:octo-synthetic");
    asset(&snapshot, AssetType::Account, "x_twitter:octo-synthetic");
    asset(&snapshot, AssetType::Account, "evilsite:octo-synthetic");
    let profile = asset(
        &snapshot,
        AssetType::URL,
        "https://github.example.test/octo-synthetic",
    );
    assert_eq!(
        snapshot
            .assets
            .iter()
            .filter(|a| a.asset_type == AssetType::Account)
            .count(),
        3
    );
    assert_eq!(
        snapshot
            .assets
            .iter()
            .filter(|a| a.asset_type == AssetType::URL)
            .count(),
        2
    );
    assert!(!snapshot
        .assets
        .iter()
        .any(|a| a.canonical_identity.contains("javascript")
            || a.canonical_identity.contains("gitlab")));
    // OSINT discoveries never widen host scope.
    assert_eq!(profile.metadata["in_scope"], false);
    assert_eq!(github.metadata["in_scope"], false);

    let has_account = snapshot
        .relationships
        .iter()
        .filter(|r| r.relationship_type == RelationshipType::HasAccount)
        .collect::<Vec<_>>();
    assert_eq!(has_account.len(), 3);
    assert!(has_account.iter().all(|r| r.source_asset_id == subject.id));
    assert!(snapshot.relationships.iter().any(|r| {
        r.relationship_type == RelationshipType::ProfileUrl
            && r.source_asset_id == github.id
            && r.destination_asset_id == profile.id
    }));

    // Evidence-first: the JSON report is its own hashed evidence record, the
    // envelope references it, and observations link to the report.
    let evidence: Vec<_> = snapshot
        .evidence
        .iter()
        .filter(|e| e.provider_run_id == run.id)
        .collect();
    assert_eq!(evidence.len(), 2);
    let envelope_id = run.raw_output_reference.unwrap();
    let envelope: Value =
        serde_json::from_str(&engine.store.read_evidence(ws, envelope_id).unwrap()).unwrap();
    let report_id: Id =
        serde_json::from_value(envelope["artifacts"][0]["evidence_id"].clone()).unwrap();
    let report_raw = engine.store.read_evidence(ws, report_id).unwrap();
    assert_eq!(
        report_raw,
        fs::read_to_string(fixture("user-scanner/username-octo-1.5.2.1.json")).unwrap(),
        "the upstream report is preserved byte-for-byte"
    );
    let report_meta = snapshot
        .evidence
        .iter()
        .find(|e| e.id == report_id)
        .unwrap();
    assert_eq!(envelope["artifacts"][0]["sha256"], report_meta.sha256);
    assert_eq!(envelope["provider"], "user_scanner");
    assert_eq!(envelope["cancelled"], false);
    let command: Vec<String> = serde_json::from_value(envelope["command"].clone()).unwrap();
    assert!(command.contains(&"--username=octo-synthetic".to_owned()));
    assert!(command.contains(&"<private-run-dir>/results.json".to_owned()));
    for forbidden in ["--cross-scan", "--hudson", "--proxy-file", "--allow-loud"] {
        assert!(!command.iter().any(|a| a.starts_with(forbidden)));
    }

    // Per-run observation keeps provider/upstream status/confidence separately.
    let account_obs = snapshot
        .observations
        .iter()
        .find(|o| o.asset_id == github.id)
        .unwrap();
    assert_eq!(account_obs.confidence, "REPORTED");
    assert_eq!(account_obs.discovered_by, "user-scanner");
    assert_eq!(account_obs.provider_run_id, Some(run.id));
    assert_eq!(account_obs.evidence_id, Some(report_id));
    let meta = account_obs.metadata.as_ref().unwrap();
    assert_eq!(meta["upstream_status"], "Found");
    assert_eq!(meta["status"], "POSITIVE");
    assert_eq!(meta["platform"], "Github");
    assert_eq!(meta["profile"]["followers"], 42);
    assert!(!meta["profile"]["bio"].as_str().unwrap().contains('\u{1b}'));
    assert!(meta["identity_note"]
        .as_str()
        .unwrap()
        .contains("not proof"));

    let summary_obs = snapshot
        .observations
        .iter()
        .find(|o| o.asset_id == subject.id && o.provider_run_id == Some(run.id))
        .unwrap();
    let summary = summary_obs.metadata.as_ref().unwrap();
    assert_eq!(summary["counts"]["positive"], 4);
    assert_eq!(summary["counts"]["negative"], 2);
    assert_eq!(summary["counts"]["error"], 1);
    assert_eq!(summary["counts"]["blocked"], 1);
    assert_eq!(summary["duplicates"], 1);
    assert_eq!(summary["urls_rejected"], 1);
    assert_eq!(summary["errors"][0]["platform"], "Instagram");
    assert_eq!(summary["partial"], true);

    let results = snapshot
        .events
        .iter()
        .find(|e| e.event_type == EventType::ProviderResults)
        .unwrap();
    assert_eq!(results.payload["partial"], true);
    assert_eq!(results.payload["summary"]["counts"]["positive"], 4);
}

#[test]
fn email_osint_end_to_end_records_registrations_without_urls() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(temp.path(), tools());
    let ws = workspace(&engine);
    let snapshot = run(
        &engine,
        ws,
        "researcher@example.test",
        ChainKind::EmailOsint,
    );
    assert_eq!(snapshot.chains[0].name, "Email OSINT");
    // Only a policy-skipped (blocked) loud module: complete, not partial.
    assert_eq!(snapshot.chains[0].status, ChainStatus::Completed);
    let subject = asset(
        &snapshot,
        AssetType::EmailAddress,
        "researcher@example.test",
    );
    let amazon = asset(
        &snapshot,
        AssetType::Account,
        "amazon:researcher@example.test",
    );
    asset(
        &snapshot,
        AssetType::Account,
        "gravatar:researcher@example.test",
    );
    asset(
        &snapshot,
        AssetType::URL,
        "https://gravatar.example.test/researcher",
    );
    assert!(snapshot
        .relationships
        .iter()
        .any(|r| r.source_asset_id == subject.id
            && r.destination_asset_id == amazon.id
            && r.relationship_type == RelationshipType::HasAccount));
    let envelope: Value = serde_json::from_str(
        &engine
            .store
            .read_evidence(ws, snapshot.provider_runs[0].raw_output_reference.unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(envelope["command"]
        .as_array()
        .unwrap()
        .contains(&json!("--email=researcher@example.test")));
    let summary = snapshot
        .observations
        .iter()
        .find(|o| o.asset_id == subject.id && o.provider_run_id.is_some())
        .and_then(|o| o.metadata.clone())
        .unwrap();
    assert_eq!(summary["counts"]["blocked"], 1);
    assert_eq!(summary["blocked"][0]["platform"], "Leetcode");
    assert_eq!(summary["subject_kind"], "EMAIL");
}

#[test]
fn repeat_runs_deduplicate_assets_keep_per_run_observations_and_survive_restart() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("store");
    let (ws, first) = {
        let engine = open(&root, tools());
        let ws = workspace(&engine);
        let target = engine.store.add_target(ws, "@octo-synthetic").unwrap();
        engine
            .start(ws, target.id, ChainKind::UsernameOsint, Value::Null)
            .unwrap();
        let first = wait(&engine, ws);
        engine
            .start(ws, target.id, ChainKind::UsernameOsint, Value::Null)
            .unwrap();
        wait(&engine, ws);
        engine.shutdown();
        (ws, first)
    };
    // Restart: a fresh engine over the same storage sees everything.
    let engine = open(&root, tools());
    let after = engine.store.snapshot(ws).unwrap();
    assert_eq!(after.chains.len(), 2);
    assert!(after
        .chains
        .iter()
        .all(|c| c.status == ChainStatus::Partial));
    assert_eq!(
        after.assets.len(),
        first.assets.len(),
        "canonical assets deduplicate"
    );
    assert_eq!(after.relationships.len(), first.relationships.len());
    let github = asset(&after, AssetType::Account, "github:octo-synthetic");
    let runs: Vec<Option<Id>> = after
        .observations
        .iter()
        .filter(|o| o.asset_id == github.id)
        .map(|o| o.provider_run_id)
        .collect();
    assert_eq!(runs.len(), 2, "one observation per run");
    assert_ne!(runs[0], runs[1]);
    assert!(after
        .observations
        .iter()
        .filter(|o| o.asset_id == github.id)
        .all(|o| o.metadata.as_ref().unwrap()["upstream_status"] == "Found"));
    for evidence in &after.evidence {
        engine.store.read_evidence(ws, evidence.id).unwrap();
    }
}

#[test]
fn workflow_and_provider_compatibility_is_enforced() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(temp.path(), tools());
    let ws = workspace(&engine);
    let user = engine.store.add_target(ws, "@octo-synthetic").unwrap();
    let email = engine
        .store
        .add_target(ws, "researcher@example.test")
        .unwrap();
    let domain = engine.store.add_target(ws, "example.test").unwrap();
    let code = |target: Id, kind, options: Value| {
        engine
            .start(ws, target, kind, options)
            .map(|_| ())
            .unwrap_err()
            .code
    };
    assert_eq!(
        code(email.id, ChainKind::UsernameOsint, Value::Null),
        "InvalidTarget"
    );
    assert_eq!(
        code(user.id, ChainKind::EmailOsint, Value::Null),
        "InvalidTarget"
    );
    assert_eq!(
        code(domain.id, ChainKind::UsernameOsint, Value::Null),
        "InvalidTarget"
    );
    assert_eq!(
        code(
            user.id,
            ChainKind::UsernameOsint,
            json!({"provider_id": "nmap"})
        ),
        "ProviderUnsupported"
    );
    assert_eq!(
        code(
            user.id,
            ChainKind::UsernameOsint,
            json!({"provider_id": "sherlock"})
        ),
        "ProviderUnsupported"
    );
    assert_eq!(
        code(user.id, ChainKind::UsernameOsint, json!({"provider_id": 5})),
        "InvalidRequest"
    );
    // A host-based chain still refuses an identifier target.
    assert!(engine
        .start(ws, user.id, ChainKind::DnsRecon, Value::Null)
        .is_err());
    // Explicit, compatible provider selection works.
    engine
        .start(
            ws,
            user.id,
            ChainKind::UsernameOsint,
            json!({"provider_id": "user_scanner"}),
        )
        .unwrap();
    assert_eq!(wait(&engine, ws).chains.len(), 1);
}

#[test]
fn missing_provider_fails_cleanly() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = ToolConfig::default();
    config
        .overrides
        .insert("user-scanner".into(), temp.path().join("absent"));
    let engine = open(&temp.path().join("store"), config);
    let ws = workspace(&engine);
    let snapshot = run(&engine, ws, "@octo-synthetic", ChainKind::UsernameOsint);
    assert_eq!(snapshot.chains[0].status, ChainStatus::Failed);
    assert_eq!(
        snapshot.chains[0].error_code.as_deref(),
        Some("ProviderMissing")
    );
}

fn failed_run_keeps_evidence(target: &str, expected_error: &str) -> (Snapshot, Value) {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(temp.path(), tools());
    let ws = workspace(&engine);
    let snapshot = run(&engine, ws, target, ChainKind::UsernameOsint);
    let chain = &snapshot.chains[0];
    assert_eq!(chain.status, ChainStatus::Failed, "{target}");
    assert_eq!(
        chain.error_code.as_deref(),
        Some(expected_error),
        "{target}"
    );
    let run = &snapshot.provider_runs[0];
    assert_eq!(run.status, TaskStatus::Failed);
    let envelope: Value = serde_json::from_str(
        &engine
            .store
            .read_evidence(ws, run.raw_output_reference.expect("envelope kept"))
            .unwrap(),
    )
    .unwrap();
    assert!(!snapshot
        .assets
        .iter()
        .any(|a| a.asset_type == AssetType::Account));
    (snapshot, envelope)
}

#[test]
fn malformed_report_fails_but_preserves_raw_report_and_envelope() {
    let (snapshot, envelope) = failed_run_keeps_evidence("@malformed-synthetic", "ProviderFailure");
    assert_eq!(snapshot.evidence.len(), 2, "raw report + envelope");
    assert!(envelope["artifacts"][0]["evidence_id"].is_string());
    let failure = snapshot
        .events
        .iter()
        .rfind(|e| e.event_type == EventType::ProviderCompleted)
        .unwrap();
    assert_eq!(failure.payload["status"], "FAILED");
    assert_eq!(failure.payload["error_code"], "ProviderFailure");
}

#[test]
fn missing_report_and_tool_failure_preserve_output() {
    let (_, envelope) = failed_run_keeps_evidence("@noreport-synthetic", "ProviderFailure");
    assert_eq!(envelope["artifacts"], json!([]));
    let (_, envelope) = failed_run_keeps_evidence("@failing-synthetic", "ProviderFailure");
    assert_eq!(envelope["exit_status"], 2);
    assert!(envelope["stderr"]
        .as_str()
        .unwrap()
        .contains("synthetic failure"));
}

#[test]
fn cancellation_terminates_the_scan_and_keeps_captured_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(temp.path(), tools());
    let ws = workspace(&engine);
    let target = engine.store.add_target(ws, "@slow-synthetic").unwrap();
    let chain = engine
        .start(ws, target.id, ChainKind::UsernameOsint, Value::Null)
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let s = engine.store.snapshot(ws).unwrap();
        if s.provider_runs
            .iter()
            .any(|r| r.status == TaskStatus::Running)
        {
            break;
        }
        assert!(Instant::now() < deadline, "provider never started");
        thread::sleep(Duration::from_millis(10));
    }
    thread::sleep(Duration::from_millis(100));
    let started = Instant::now();
    engine.cancel(ws, chain.id).unwrap();
    let snapshot = wait(&engine, ws);
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "cancel is prompt"
    );
    assert_eq!(snapshot.chains[0].status, ChainStatus::Cancelled);
    let run = &snapshot.provider_runs[0];
    assert_eq!(run.status, TaskStatus::Cancelled);
    let envelope: Value = serde_json::from_str(
        &engine
            .store
            .read_evidence(
                ws,
                run.raw_output_reference.expect("evidence kept on cancel"),
            )
            .unwrap(),
    )
    .unwrap();
    assert_eq!(envelope["cancelled"], true);
    assert!(envelope["stdout"]
        .as_str()
        .unwrap()
        .contains("Checking target: slow-synthetic"));
}

#[test]
fn provider_timeout_kills_the_scan_without_structured_results() {
    let tools = tools();
    let cancelled = AtomicBool::new(false);
    let started = Instant::now();
    let ctx = ProviderContext {
        cancelled: &cancelled,
        deadline: Instant::now() + Duration::from_millis(500),
        tools: &tools,
        scope: &[],
        options: &Value::Null,
    };
    let execution = UserScannerProvider
        .execute("@slow-synthetic", Capability::UsernameOsint, &[], &ctx)
        .unwrap();
    assert!(execution.timed_out && !execution.succeeded());
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(execution.artifacts.is_empty());
}

#[test]
fn chatty_output_is_bounded_and_the_run_still_completes() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(temp.path(), tools());
    let ws = workspace(&engine);
    let snapshot = run(&engine, ws, "@flood-synthetic", ChainKind::UsernameOsint);
    assert_ne!(snapshot.chains[0].status, ChainStatus::Failed);
    let envelope: Value = serde_json::from_str(
        &engine
            .store
            .read_evidence(ws, snapshot.provider_runs[0].raw_output_reference.unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(envelope["stdout"].as_str().unwrap().len() <= 256 * 1024);
}
