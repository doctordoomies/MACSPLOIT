//! Offline coverage for the app-managed Python installer (pinned `uv`). Uses a fake
//! `uv` executable and an empty download transport — no network, no real uv, no PyPI.

use macsploit_core::{
    database::Store,
    dns::StaticDnsResolver,
    install::{self, InstallMethod},
    orchestration::Engine,
    process::ToolConfig,
    web::StaticWebTransport,
};
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{atomic::AtomicBool, Arc, Mutex},
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

fn tools(managed: &Path) -> ToolConfig {
    let mut t = ToolConfig {
        managed_dir: Some(managed.to_path_buf()),
        ..Default::default()
    };
    t.overrides.insert("uv".into(), fixture("fake-uv.sh"));
    t
}

/// A reporter that records every event for assertions.
#[derive(Default)]
struct Recorder {
    events: Mutex<Vec<(String, String)>>,
}
impl install::InstallReporter for Recorder {
    fn event(&self, kind: install::InstallEventKind, text: &str) {
        self.events
            .lock()
            .unwrap()
            .push((format!("{kind:?}"), text.to_owned()));
    }
}

#[test]
fn managed_method_resolves_per_provider() {
    assert_eq!(
        install::managed_method("sherlock"),
        Some(InstallMethod::ManagedPython)
    );
    assert_eq!(
        install::managed_method("maigret"),
        Some(InstallMethod::ManagedPython)
    );
    assert_eq!(
        install::managed_method("socialscan"),
        Some(InstallMethod::ManagedPython)
    );
    assert_eq!(
        install::managed_method("user_scanner"),
        Some(InstallMethod::ManagedPython)
    );
    assert_eq!(
        install::managed_method("subfinder"),
        Some(InstallMethod::ManagedDownload)
    );
    // Homebrew/official-only providers have no app-managed method.
    assert_eq!(install::managed_method("nmap"), None);
    assert_eq!(install::managed_method("phoneinfoga"), None);
    assert_eq!(install::managed_method("totally-unknown"), None);
}

#[test]
fn python_install_uses_uv_writes_console_script_and_is_discoverable() {
    let temp = tempfile::tempdir().unwrap();
    let managed = temp.path().join("Providers");
    let tools = tools(&managed);
    let downloader = install::download::StaticDownloadTransport::new(); // never used (uv override present)
    let recorder = Recorder::default();

    let outcome = install::python::python_install(
        &tools,
        &downloader,
        &recorder,
        "sherlock",
        &AtomicBool::new(false),
        Instant::now() + Duration::from_secs(30),
    )
    .unwrap();

    assert_eq!(outcome.status, install::InstallStatus::Succeeded);
    // The reviewed console script landed in the managed Python bin dir and is runnable.
    let script = managed.join("python-bin").join("sherlock");
    assert!(script.exists());
    assert!(script.metadata().unwrap().permissions().mode() & 0o111 != 0);
    // The same ToolConfig now discovers it (python-bin is on the search path).
    assert_eq!(
        tools.locate("sherlock"),
        Some(script.canonicalize().unwrap())
    );
    // The console recorded a reviewed command and real output — never a shell string.
    let events = recorder.events.lock().unwrap();
    assert!(events
        .iter()
        .any(|(k, t)| k == "Command" && t.contains("tool install")));
    assert!(events.iter().any(|(k, _)| k == "Stdout"));
    assert!(events
        .iter()
        .any(|(k, t)| k == "Stage" && t == "INSTALLING"));
    assert!(events.iter().any(|(k, t)| k == "Stage" && t == "CHECKING"));
}

#[test]
fn python_install_failure_leaves_no_script() {
    let temp = tempfile::tempdir().unwrap();
    let managed = temp.path().join("Providers");
    let mut tools = tools(&managed);
    // A uv that fails: wrap the fake with the FAKE_UV_FAIL knob via a tiny shim.
    let shim = temp.path().join("uv-fail.sh");
    std::fs::write(
        &shim,
        format!(
            "#!/bin/sh\nexport FAKE_UV_FAIL=1\nexec {} \"$@\"\n",
            fixture("fake-uv.sh").display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
    tools.overrides.insert("uv".into(), shim);

    let outcome = install::python::python_install(
        &tools,
        &install::download::StaticDownloadTransport::new(),
        &install::NullReporter,
        "maigret",
        &AtomicBool::new(false),
        Instant::now() + Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(outcome.status, install::InstallStatus::Failed);
    assert!(!managed.join("python-bin").join("maigret").exists());
}

fn engine(tools: ToolConfig, root: &Path) -> Engine {
    Engine::open_with_download(
        Store::open(root).unwrap(),
        Duration::ZERO,
        tools,
        Arc::new(StaticDnsResolver::new()),
        Arc::new(StaticWebTransport::new()),
        Arc::new(install::download::StaticDownloadTransport::new()),
    )
    .unwrap()
}

fn wait_last(engine: &Engine) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(30);
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
fn engine_install_with_macsploit_streams_events_and_rediscovers_provider() {
    let temp = tempfile::tempdir().unwrap();
    let managed = temp.path().join("Providers");
    let engine = engine(tools(&managed), &temp.path().join("store"));

    // "Install with MACSPLOIT" → the core resolves the managed Python method.
    let ack = engine
        .start_install("socialscan", InstallMethod::Managed)
        .unwrap();
    assert_eq!(ack["started"], serde_json::json!(true));

    let status = wait_last(&engine);
    assert_eq!(status["last"]["status"], serde_json::json!("SUCCEEDED"));
    // The resolved concrete method is reported for the console/UI.
    assert_eq!(
        status["last"]["method"],
        serde_json::json!("managed_python")
    );
    // The event stream drove a live Install Console: stages + a reviewed command.
    let events = status["events"].as_array().expect("events array");
    assert!(events
        .iter()
        .any(|e| e["kind"] == "STAGE" && e["text"] == "READY"));
    assert!(events
        .iter()
        .any(|e| e["kind"] == "COMMAND" && e["text"].as_str().unwrap().contains("tool install")));

    // Rediscovery: the provider is now installed without a manual refresh.
    let socialscan = engine
        .providers()
        .into_iter()
        .find(|p| p.metadata.id == "socialscan")
        .unwrap();
    assert!(
        matches!(
            socialscan.installation,
            macsploit_core::process::Installation::Installed { .. }
        ),
        "socialscan should be installed after the managed install"
    );
}
