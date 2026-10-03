//! Phase 2B end-to-end coverage for native HTTP/web analysis, driven entirely
//! offline through a static web transport. No network access occurs.

use macsploit_core::{
    assets::{AssetType, Id},
    database::Store,
    dns::StaticDnsResolver,
    events::ChainStatus,
    orchestration::{ChainKind, Engine, Snapshot},
    process::ToolConfig,
    web::StaticWebTransport,
};
use std::{
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

fn wait(engine: &Engine, workspace: Id) -> Snapshot {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !engine.idle() {
        assert!(Instant::now() < deadline, "chain timed out");
        thread::sleep(Duration::from_millis(5));
    }
    engine.store.snapshot(workspace).unwrap()
}

#[test]
fn web_analysis_runs_natively_end_to_end_and_persists() {
    let temp = tempfile::tempdir().unwrap();
    let transport = StaticWebTransport::new()
        .with_response(
            "https://example.test/",
            200,
            &[
                ("Server", "nginx"),
                ("Content-Type", "text/html"),
                ("Strict-Transport-Security", "max-age=63072000"),
                ("Content-Security-Policy", "default-src 'self'"),
                ("Access-Control-Allow-Origin", "https://example.test"),
                (
                    "Set-Cookie",
                    "sid=TOPSECRET; Secure; HttpOnly; SameSite=Strict; Path=/",
                ),
            ],
            "<html></html>",
        )
        .with_response(
            "https://example.test/robots.txt",
            200,
            &[],
            "User-agent: *\nDisallow: /admin\n",
        );
    let engine = Engine::open_with_web(
        Store::open(temp.path()).unwrap(),
        Duration::ZERO,
        ToolConfig::default(),
        Arc::new(StaticDnsResolver::new()),
        Arc::new(transport),
    )
    .unwrap();
    let workspace = engine
        .store
        .create_workspace("Web", &["example.test".into(), "*.example.test".into()])
        .unwrap();
    let target = engine
        .store
        .add_target(workspace.id, "https://example.test/")
        .unwrap();

    engine
        .start(
            workspace.id,
            target.id,
            ChainKind::WebAnalysis,
            serde_json::Value::Null,
        )
        .unwrap();
    let snapshot = wait(&engine, workspace.id);

    assert_eq!(snapshot.chains[0].name, "Web Analysis");
    assert_eq!(snapshot.chains[0].status, ChainStatus::Completed);
    assert!(snapshot.stages.iter().any(
        |s| s.name == "Native HTTP Analysis" && s.provider_id.as_deref() == Some("native_http")
    ));

    // A Website asset for the URL exists and is attributed to native HTTP analysis.
    let website = snapshot
        .assets
        .iter()
        .find(|a| {
            a.asset_type == AssetType::Website && a.canonical_identity == "https://example.test/"
        })
        .expect("website asset");
    assert_eq!(website.metadata["tool"], serde_json::json!("native_http"));

    // One built-in provider run, completed, core version.
    assert_eq!(snapshot.provider_runs.len(), 1);
    let run = &snapshot.provider_runs[0];
    assert_eq!(run.provider_id, "native_http");
    assert!(run.provider_version.starts_with("core "));
    assert!(run.raw_output_reference.is_some());

    // Observation attributes the website to the provider run + evidence.
    assert!(snapshot
        .observations
        .iter()
        .any(|o| o.asset_id == website.id
            && o.discovered_by == "Native HTTP Analysis"
            && o.provider_run_id == Some(run.id)
            && o.evidence_id.is_some()));

    // Evidence captures normalized security metadata — and never the cookie value.
    assert_eq!(snapshot.evidence.len(), 1);
    let raw = engine
        .store
        .read_evidence(workspace.id, snapshot.evidence[0].id)
        .unwrap();
    assert!(raw.contains("strict-transport-security"));
    assert!(raw.contains("http_only")); // cookie flags captured (value precision covered by unit tests)
    assert!(raw.contains("/admin")); // robots parsed
    assert!(
        !raw.contains("TOPSECRET"),
        "cookie value must not be persisted"
    );

    // Persistence across a database reopen.
    drop(engine);
    let reopened = Engine::open_with_web(
        Store::open(temp.path()).unwrap(),
        Duration::ZERO,
        ToolConfig::default(),
        Arc::new(StaticDnsResolver::new()),
        Arc::new(StaticWebTransport::new()),
    )
    .unwrap();
    let after = reopened.store.snapshot(workspace.id).unwrap();
    assert_eq!(after.provider_runs.len(), 1);
    assert_eq!(after.evidence.len(), 1);
    assert!(after
        .assets
        .iter()
        .any(|a| a.asset_type == AssetType::Website
            && a.canonical_identity == "https://example.test/"));
    assert_eq!(after.chains[0].status, ChainStatus::Completed);
}

#[test]
fn web_analysis_runs_against_localhost_with_custom_port_and_follows_in_scope_redirect() {
    // A locally running app on a custom port, authorized by an explicit `localhost`
    // scope entry. No public DNS, no Domain target. An in-scope relative redirect is
    // followed and the custom port is preserved end to end.
    let temp = tempfile::tempdir().unwrap();
    let transport = StaticWebTransport::new()
        .with_response("http://localhost:3000/", 301, &[("Location", "/login")], "")
        .with_response(
            "http://localhost:3000/login",
            200,
            &[
                ("Server", "devserver"),
                ("X-Frame-Options", "DENY"),
                ("Set-Cookie", "sid=LOCALSECRET; HttpOnly; Path=/"),
            ],
            "<html></html>",
        )
        .with_response(
            "http://localhost:3000/robots.txt",
            200,
            &[],
            "User-agent: *\nDisallow: /admin\n",
        );
    let engine = Engine::open_with_web(
        Store::open(temp.path()).unwrap(),
        Duration::ZERO,
        ToolConfig::default(),
        Arc::new(StaticDnsResolver::new()),
        Arc::new(transport),
    )
    .unwrap();
    let workspace = engine
        .store
        .create_workspace("Local App", &["localhost".into()])
        .unwrap();
    let target = engine
        .store
        .add_target(workspace.id, "http://localhost:3000/")
        .unwrap();

    engine
        .start(
            workspace.id,
            target.id,
            ChainKind::WebAnalysis,
            serde_json::Value::Null,
        )
        .unwrap();
    let snapshot = wait(&engine, workspace.id);
    assert_eq!(snapshot.chains[0].status, ChainStatus::Completed);

    // The Website asset is the followed, in-scope destination with its custom port.
    assert!(snapshot
        .assets
        .iter()
        .any(|a| a.asset_type == AssetType::Website
            && a.canonical_identity == "http://localhost:3000/login"));

    let raw = engine
        .store
        .read_evidence(workspace.id, snapshot.evidence[0].id)
        .unwrap();
    assert!(raw.contains("localhost:3000"));
    assert!(raw.contains("/admin")); // robots fetched on the custom-port host
    assert!(!raw.contains("LOCALSECRET")); // cookie value never persisted
}

#[test]
fn web_analysis_does_not_follow_a_cross_host_local_redirect() {
    // localhost and 127.0.0.1 are distinct authorization identities: a redirect from an
    // authorized localhost target to an unauthorized loopback literal is recorded but
    // never followed (fail closed), even though both are "local".
    let temp = tempfile::tempdir().unwrap();
    let transport = StaticWebTransport::new()
        .with_response(
            "http://localhost:3000/",
            302,
            &[("Location", "http://127.0.0.1:9000/")],
            "",
        )
        .with_response("http://localhost:3000/robots.txt", 404, &[], "");
    let engine = Engine::open_with_web(
        Store::open(temp.path()).unwrap(),
        Duration::ZERO,
        ToolConfig::default(),
        Arc::new(StaticDnsResolver::new()),
        Arc::new(transport),
    )
    .unwrap();
    let workspace = engine
        .store
        .create_workspace("Local App", &["localhost".into()])
        .unwrap();
    let target = engine
        .store
        .add_target(workspace.id, "http://localhost:3000/")
        .unwrap();

    engine
        .start(
            workspace.id,
            target.id,
            ChainKind::WebAnalysis,
            serde_json::Value::Null,
        )
        .unwrap();
    let snapshot = wait(&engine, workspace.id);
    assert_eq!(snapshot.chains[0].status, ChainStatus::Completed);

    // Website identity stays on the authorized host; the cross-host hop is not followed.
    assert!(snapshot
        .assets
        .iter()
        .any(|a| a.asset_type == AssetType::Website
            && a.canonical_identity == "http://localhost:3000/"));
    assert!(!snapshot
        .assets
        .iter()
        .any(|a| a.canonical_identity.contains("127.0.0.1")));
    let raw = engine
        .store
        .read_evidence(workspace.id, snapshot.evidence[0].id)
        .unwrap();
    assert!(raw.contains("out-of-scope host not followed"));
}

#[test]
fn web_analysis_requires_in_scope_url() {
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::open_with_web(
        Store::open(temp.path()).unwrap(),
        Duration::ZERO,
        ToolConfig::default(),
        Arc::new(StaticDnsResolver::new()),
        Arc::new(StaticWebTransport::new()),
    )
    .unwrap();
    let workspace = engine
        .store
        .create_workspace("Web", &["example.test".into()])
        .unwrap();
    let outside = engine
        .store
        .add_target(workspace.id, "https://other.test/")
        .unwrap();
    let error = engine
        .start(
            workspace.id,
            outside.id,
            ChainKind::WebAnalysis,
            serde_json::Value::Null,
        )
        .unwrap_err();
    assert_eq!(error.code, "ScopeViolation");
}
