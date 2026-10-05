//! Async provider-install flow coverage. Uses a fake `brew` executable only; no real
//! Homebrew and no network.

use macsploit_core::{
    database::Store, install::InstallMethod, orchestration::Engine, process::ToolConfig,
};
use std::{
    os::unix::fs::PermissionsExt,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

fn fake_brew(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
    let p = dir.join("brew");
    std::fs::write(&p, body).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

fn engine(tools: ToolConfig) -> (tempfile::TempDir, Engine) {
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::open_with(
        Store::open(temp.path()).unwrap(),
        Duration::ZERO,
        tools,
        Arc::new(macsploit_core::dns::StaticDnsResolver::new()),
    )
    .unwrap();
    (temp, engine)
}

fn wait_last(engine: &Engine) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let status = engine.install_status().unwrap();
        if !status["last"].is_null() {
            return status;
        }
        assert!(Instant::now() < deadline, "install did not finish");
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn homebrew_install_runs_async_and_reports_success() {
    let dir = tempfile::tempdir().unwrap();
    let args_file = dir.path().join("args.txt");
    let brew = fake_brew(
        dir.path(),
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\nexit 0\n",
            args_file.display()
        ),
    );
    let mut tools = ToolConfig::default();
    tools.overrides.insert("brew".into(), brew);
    let (_t, engine) = engine(tools);

    let ack = engine
        .start_install("subfinder", InstallMethod::Homebrew)
        .unwrap();
    assert_eq!(ack["started"], serde_json::json!(true));
    let status = wait_last(&engine);
    assert_eq!(status["last"]["status"], serde_json::json!("SUCCEEDED"));
    assert!(status["running"].is_null());
    // Shell-free: fake brew saw exactly ["install", "subfinder"].
    let recorded = std::fs::read_to_string(&args_file).unwrap();
    assert_eq!(
        recorded.lines().collect::<Vec<_>>(),
        vec!["install", "subfinder"]
    );
}

#[test]
fn unknown_provider_cannot_start_install() {
    let (_t, engine) = engine(ToolConfig::default());
    let err = engine
        .start_install("evil", InstallMethod::Homebrew)
        .unwrap_err();
    assert_eq!(err.code, "ProviderUnsupported");
}

#[test]
fn managed_download_fails_closed_without_installing() {
    let (_t, engine) = engine(ToolConfig::default());
    engine
        .start_install("ffuf", InstallMethod::ManagedDownload)
        .unwrap();
    let status = wait_last(&engine);
    assert_eq!(status["last"]["status"], serde_json::json!("UNSUPPORTED"));
}

#[test]
fn second_install_is_rejected_while_one_runs() {
    let dir = tempfile::tempdir().unwrap();
    // A brew that blocks briefly so the first install is still "running".
    let brew = fake_brew(dir.path(), "#!/bin/sh\nsleep 1\nexit 0\n");
    let mut tools = ToolConfig::default();
    tools.overrides.insert("brew".into(), brew);
    let (_t, engine) = engine(tools);
    engine
        .start_install("httpx", InstallMethod::Homebrew)
        .unwrap();
    let err = engine
        .start_install("katana", InstallMethod::Homebrew)
        .unwrap_err();
    assert_eq!(err.code, "CoreBusy");
    wait_last(&engine); // let the first finish so the worker thread drains
}
