//! Milestone 6.3 / Issue #65: Phone OSINT via PhoneInfoga, driven entirely offline
//! by `fixtures/fake-phoneinfoga.sh` with fictional numbers. No network.

use macsploit_core::{
    assets::{AssetType, Id},
    database::Store,
    dns::StaticDnsResolver,
    events::{ChainStatus, TaskStatus},
    orchestration::{ChainKind, Engine, Snapshot},
    process::{Installation, ToolConfig},
    providers::{Capability, PhoneInfogaProvider, Provider, ProviderContext, ProviderRegistry},
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
        .insert("phoneinfoga".into(), fixture("fake-phoneinfoga.sh"));
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
    // Host scope deliberately covers nothing related to the phone subject.
    engine
        .store
        .create_workspace("Phone OSINT", &["example.test".into()])
        .unwrap()
        .id
}

fn wait(engine: &Engine, ws: Id) -> Snapshot {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !engine.idle() {
        assert!(Instant::now() < deadline, "chain timed out");
        thread::sleep(Duration::from_millis(5));
    }
    engine.store.snapshot(ws).unwrap()
}

fn run(engine: &Engine, ws: Id, number: &str) -> Snapshot {
    let target = engine.store.add_target(ws, number).unwrap();
    engine
        .start(ws, target.id, ChainKind::PhoneOsint, Value::Null)
        .unwrap();
    wait(engine, ws)
}

fn envelope(engine: &Engine, ws: Id, snap: &Snapshot) -> Value {
    let run = snap.provider_runs.last().unwrap();
    serde_json::from_str(
        &engine
            .store
            .read_evidence(ws, run.raw_output_reference.expect("evidence kept"))
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn provider_center_reports_version_unsupported_and_missing() {
    let registry = ProviderRegistry::default();
    let status = |tools: &ToolConfig| {
        registry
            .status(tools)
            .into_iter()
            .find(|s| s.metadata.id == "phoneinfoga")
            .unwrap()
    };
    let installed = status(&tools());
    assert_eq!(
        installed.installation,
        Installation::Installed {
            version: "2.11.0".into(),
            path: Some(fixture("fake-phoneinfoga.sh")),
        }
    );
    assert_eq!(
        installed.metadata.capabilities,
        vec![Capability::PhoneOsint]
    );
    assert_eq!(
        installed.setup.unwrap().install_command.as_deref(),
        Some("brew install phoneinfoga")
    );

    let temp = tempfile::tempdir().unwrap();
    let old = temp.path().join("phoneinfoga");
    fs::write(&old, "#!/bin/sh\necho 'PhoneInfoga v1.10.0-abc'\n").unwrap();
    fs::set_permissions(&old, fs::Permissions::from_mode(0o755)).unwrap();
    let mut config = ToolConfig::default();
    config.overrides.insert("phoneinfoga".into(), old);
    assert_eq!(
        status(&config).installation,
        Installation::UnsupportedVersion {
            version: "1.10.0".into()
        }
    );
    let mut missing = ToolConfig::default();
    missing
        .overrides
        .insert("phoneinfoga".into(), temp.path().join("absent"));
    assert_eq!(status(&missing).installation, Installation::Missing);
}

#[test]
fn phone_targets_require_international_format() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(temp.path(), tools());
    let ws = workspace(&engine);
    let target = engine.store.add_target(ws, "+33 1 99 00 12 34").unwrap();
    assert_eq!(target.normalized_value, "+33199001234");
    assert_eq!(
        target.original_value, "+33 1 99 00 12 34",
        "original input kept"
    );
    let err = engine.store.add_target(ws, "(202) 555-0143").unwrap_err();
    assert!(err.message.contains("does not guess the country"));
    // Adding a phone target launches nothing.
    assert!(engine.store.snapshot(ws).unwrap().chains.is_empty());
}

#[test]
fn phone_osint_end_to_end_dedups_repeat_runs_and_survives_restart() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("store");
    let ws = {
        let engine = open(&root, tools());
        let ws = workspace(&engine);
        let first = run(&engine, ws, "+33199001234");
        assert_eq!(first.chains[0].name, "Phone OSINT");
        assert_eq!(first.chains[0].status, ChainStatus::Completed);
        assert_eq!(first.provider_runs[0].provider_version, "2.11.0");
        let env = envelope(&engine, ws, &first);
        let command: Vec<String> = serde_json::from_value(env["command"].clone()).unwrap();
        assert!(command.contains(&"--number=+33199001234".to_owned()));
        for disabled in ["numverify", "googlecse", "googlesearch"] {
            assert!(command.contains(&format!("--disable={disabled}")));
        }
        let target = first.targets[0].id;
        engine
            .start(ws, target, ChainKind::PhoneOsint, Value::Null)
            .unwrap();
        wait(&engine, ws);
        engine.shutdown();
        ws
    };
    let engine = open(&root, tools());
    let snap = engine.store.snapshot(ws).unwrap();
    let phones: Vec<_> = snap
        .assets
        .iter()
        .filter(|a| a.asset_type == AssetType::PhoneNumber)
        .collect();
    assert_eq!(phones.len(), 1, "canonical phone asset deduplicates");
    assert_eq!(
        snap.assets.len(),
        1,
        "no accounts, people, or pivots created"
    );
    assert_eq!(phones[0].metadata["in_scope"], false);
    let obs: Vec<_> = snap
        .observations
        .iter()
        .filter(|o| o.asset_id == phones[0].id)
        .collect();
    assert_eq!(obs.len(), 2, "one observation per run");
    assert_ne!(obs[0].provider_run_id, obs[1].provider_run_id);
    for o in &obs {
        assert_eq!(o.discovered_by, "PhoneInfoga");
        assert_eq!(o.confidence, "REPORTED");
        let meta = o.metadata.as_ref().unwrap();
        assert_eq!(meta["sources"]["local"]["country"], "FR");
        assert_eq!(meta["sources"]["ovh"]["number_range"], "0199xxxxxx");
        // The observation's evidence is this run's own raw console output.
        let raw = engine
            .store
            .read_evidence(ws, o.evidence_id.unwrap())
            .unwrap();
        assert!(raw.contains("Results for ovh"));
    }
}

#[test]
fn partial_zero_and_failure_outcomes_keep_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(temp.path(), tools());
    let ws = workspace(&engine);

    let partial = run(&engine, ws, "+12025550143");
    assert_eq!(partial.chains[0].status, ChainStatus::Partial);

    let zero = run(&engine, ws, "+12025550166");
    let chain = zero.chains.last().unwrap();
    assert_eq!(chain.status, ChainStatus::Completed);

    for (number, code) in [
        ("+12025550177", "ProviderFailure"),
        ("+12025550199", "ProviderFailure"),
        ("+12025550155", "BudgetExceeded"),
    ] {
        let snap = run(&engine, ws, number);
        let chain = snap.chains.last().unwrap();
        assert_eq!(chain.status, ChainStatus::Failed, "{number}");
        assert_eq!(chain.error_code.as_deref(), Some(code), "{number}");
        let env = envelope(&engine, ws, &snap);
        assert_eq!(
            snap.provider_runs.last().unwrap().status,
            TaskStatus::Failed
        );
        if number == "+12025550177" {
            assert!(env["stderr"].as_str().unwrap().contains("not valid"));
        }
    }
}

#[test]
fn cancellation_and_timeout_are_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(temp.path(), tools());
    let ws = workspace(&engine);
    let target = engine.store.add_target(ws, "+12025550188").unwrap();
    let chain = engine
        .start(ws, target.id, ChainKind::PhoneOsint, Value::Null)
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !engine
        .store
        .snapshot(ws)
        .unwrap()
        .provider_runs
        .iter()
        .any(|r| r.status == TaskStatus::Running)
    {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    engine.cancel(ws, chain.id).unwrap();
    let snap = wait(&engine, ws);
    assert_eq!(snap.chains[0].status, ChainStatus::Cancelled);
    assert_eq!(envelope(&engine, ws, &snap)["cancelled"], true);

    let tools = tools();
    let cancelled = AtomicBool::new(false);
    let ctx = ProviderContext {
        cancelled: &cancelled,
        deadline: Instant::now() + Duration::from_millis(400),
        tools: &tools,
        scope: &[],
        options: &Value::Null,
    };
    let started = Instant::now();
    let execution = PhoneInfogaProvider
        .execute("+12025550188", Capability::PhoneOsint, &[], &ctx)
        .unwrap();
    assert!(execution.timed_out && started.elapsed() < Duration::from_secs(10));
}

#[test]
fn phone_workflow_rejects_other_targets_and_providers() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(temp.path(), tools());
    let ws = workspace(&engine);
    let user = engine.store.add_target(ws, "@octo-synthetic").unwrap();
    let phone = engine.store.add_target(ws, "+33199001234").unwrap();
    assert_eq!(
        engine
            .start(ws, user.id, ChainKind::PhoneOsint, Value::Null)
            .unwrap_err()
            .code,
        "InvalidTarget"
    );
    for provider in ["user_scanner", "sherlock", "nmap"] {
        assert_eq!(
            engine
                .start(
                    ws,
                    phone.id,
                    ChainKind::PhoneOsint,
                    json!({"provider_id": provider})
                )
                .unwrap_err()
                .code,
            "ProviderUnsupported",
            "{provider}"
        );
    }
    // Host-based chains never accept a phone subject.
    assert!(engine
        .start(ws, phone.id, ChainKind::DnsRecon, Value::Null)
        .is_err());
}
