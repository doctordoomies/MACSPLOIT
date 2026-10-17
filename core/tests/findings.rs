//! Durable Findings foundation (Issue #76), offline. A synthetic chain produces real
//! durable Asset/Evidence/provider-run records; Findings then reference those records.
//! No network, no scanners.

use macsploit_core::{
    assets::Id,
    database::Store,
    dns::StaticDnsResolver,
    findings::{FindingConfidence, FindingEdit, FindingStatus, NewFinding, Severity},
    orchestration::{ChainKind, Engine, Snapshot},
    process::ToolConfig,
};
use serde_json::Value;
use std::{
    path::Path,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

fn open(root: &Path) -> Engine {
    Engine::open_with(
        Store::open(root).unwrap(),
        Duration::ZERO,
        ToolConfig::default(),
        Arc::new(StaticDnsResolver::new()),
    )
    .unwrap()
}

fn workspace(engine: &Engine) -> Id {
    engine
        .store
        .create_workspace(
            "Findings",
            &["example.test".into(), "*.example.test".into()],
        )
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

/// Run one synthetic chain and return (workspace, snapshot) with durable records.
fn seeded(engine: &Engine) -> (Id, Snapshot) {
    let ws = workspace(engine);
    let target = engine.store.add_target(ws, "example.test").unwrap();
    engine
        .start(ws, target.id, ChainKind::Synthetic, Value::Null)
        .unwrap();
    let snap = wait(engine, ws);
    (ws, snap)
}

fn an_asset(snap: &Snapshot) -> Id {
    snap.assets.first().expect("an asset").id
}
fn an_evidence(snap: &Snapshot) -> Id {
    snap.evidence.first().expect("evidence").id
}

#[test]
fn create_update_status_history_and_restart() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("store");
    let (ws, finding_id) = {
        let engine = open(&root);
        let (ws, snap) = seeded(&engine);
        let asset = an_asset(&snap);
        let evidence = an_evidence(&snap);
        let run = snap.provider_runs.first().map(|r| r.id);

        let finding = engine
            .store
            .create_finding(
                ws,
                NewFinding {
                    title: "Expired TLS certificate".into(),
                    severity: Severity::Medium,
                    confidence: FindingConfidence::High,
                    status: Some(FindingStatus::Open),
                    description: "The certificate presented by the service is expired.".into(),
                    reproduction: "Connect and inspect the certificate validity dates.".into(),
                    remediation: "Reissue and deploy a current certificate.".into(),
                    tags: vec!["tls".into(), "tls".into()], // dedup -> one
                    cwe_ids: vec!["cwe-295".into()],
                    cve_ids: vec![],
                    primary_asset_id: Some(asset),
                    additional_asset_ids: vec![],
                    evidence_ids: vec![evidence],
                    source_provider: Some("synthetic".into()),
                    source_run_id: run,
                },
            )
            .unwrap();

        // Three independent dimensions.
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.confidence, FindingConfidence::High);
        assert_eq!(finding.status, FindingStatus::Open);
        assert_eq!(finding.tags, vec!["tls".to_string()]);
        assert_eq!(finding.cwe_ids, vec!["CWE-295".to_string()]);
        assert_eq!(finding.affected_assets.len(), 1);
        assert!(finding.affected_assets[0].is_primary);
        assert_eq!(finding.affected_assets[0].asset_id, asset);
        assert_eq!(finding.evidence_ids, vec![evidence]);
        assert_eq!(finding.source_provider.as_deref(), Some("synthetic"));
        assert_eq!(finding.history.len(), 1);
        assert_eq!(finding.history[0].kind, "CREATED");

        // Editing severity/confidence does not change status; records history.
        let edited = engine
            .store
            .update_finding(
                ws,
                finding.id,
                FindingEdit {
                    severity: Some(Severity::High),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(edited.severity, Severity::High);
        assert_eq!(edited.status, FindingStatus::Open);
        assert!(edited.history.iter().any(|h| h.kind == "SEVERITY"));

        // Validated lifecycle transition.
        let confirmed = engine
            .store
            .set_finding_status(
                ws,
                finding.id,
                FindingStatus::Confirmed,
                "Verified by hand.",
            )
            .unwrap();
        assert_eq!(confirmed.status, FindingStatus::Confirmed);
        assert!(confirmed
            .history
            .iter()
            .any(|h| h.kind == "STATUS" && h.to_value.as_deref() == Some("CONFIRMED")));
        // Invalid transition refused.
        assert_eq!(
            engine
                .store
                .set_finding_status(ws, finding.id, FindingStatus::RetestPassed, "nope")
                .unwrap_err()
                .code,
            "InvalidTransition"
        );
        engine.shutdown();
        (ws, finding.id)
    };

    // Restart: finding, status, links, provenance, and history survive.
    let engine = open(&root);
    let snap = engine.store.snapshot(ws).unwrap();
    assert_eq!(snap.findings.len(), 1);
    let f = &snap.findings[0];
    assert_eq!(f.id, finding_id);
    assert_eq!(f.status, FindingStatus::Confirmed);
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.affected_assets.len(), 1);
    assert_eq!(f.evidence_ids.len(), 1);
    assert_eq!(f.source_provider.as_deref(), Some("synthetic"));
    assert!(f.history.iter().any(|h| h.kind == "CREATED"));
    assert!(f.history.iter().any(|h| h.kind == "STATUS"));
}

#[test]
fn cross_workspace_asset_and_evidence_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(&temp.path().join("store"));
    let (_ws1, snap1) = seeded(&engine);
    let other_asset = an_asset(&snap1);
    let other_evidence = an_evidence(&snap1);
    // A second, separate workspace.
    let ws2 = engine
        .store
        .create_workspace("Other", &["example.test".into()])
        .unwrap()
        .id;

    let asset_err = engine
        .store
        .create_finding(
            ws2,
            NewFinding {
                title: "Cross-workspace asset".into(),
                primary_asset_id: Some(other_asset),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert_eq!(asset_err.code, "AssetNotFound");

    let evidence_err = engine
        .store
        .create_finding(
            ws2,
            NewFinding {
                title: "Cross-workspace evidence".into(),
                evidence_ids: vec![other_evidence],
                ..Default::default()
            },
        )
        .unwrap_err();
    assert_eq!(evidence_err.code, "InvalidRequest");
}

#[test]
fn multiple_evidence_links_dedupe_and_unlink() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(&temp.path().join("store"));
    let (ws, snap) = seeded(&engine);
    let evidence: Vec<Id> = snap.evidence.iter().map(|e| e.id).collect();
    assert!(!evidence.is_empty());

    let finding = engine
        .store
        .create_finding(
            ws,
            NewFinding {
                title: "Multi-evidence".into(),
                ..Default::default()
            },
        )
        .unwrap();

    let linked = engine
        .store
        .link_finding_evidence(ws, finding.id, evidence[0])
        .unwrap();
    assert_eq!(linked.evidence_ids, vec![evidence[0]]);
    // Idempotent re-link does not duplicate.
    let again = engine
        .store
        .link_finding_evidence(ws, finding.id, evidence[0])
        .unwrap();
    assert_eq!(again.evidence_ids, vec![evidence[0]]);
    // Unlink leaves the finding intact (and the Evidence still exists).
    let unlinked = engine
        .store
        .unlink_finding_evidence(ws, finding.id, evidence[0])
        .unwrap();
    assert!(unlinked.evidence_ids.is_empty());
    assert!(engine.store.read_evidence(ws, evidence[0]).is_ok());
    assert!(unlinked.history.iter().any(|h| h.kind == "EVIDENCE_LINKED"));
    assert!(unlinked
        .history
        .iter()
        .any(|h| h.kind == "EVIDENCE_UNLINKED"));
}

#[test]
fn bounds_and_identifier_validation_are_enforced() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(&temp.path().join("store"));
    let ws = workspace(&engine);

    // Empty title rejected.
    assert_eq!(
        engine
            .store
            .create_finding(
                ws,
                NewFinding {
                    title: "  ".into(),
                    ..Default::default()
                }
            )
            .unwrap_err()
            .code,
        "InvalidRequest"
    );
    // Oversized description rejected (no megabytes into SQLite).
    assert_eq!(
        engine
            .store
            .create_finding(
                ws,
                NewFinding {
                    title: "Big".into(),
                    description: "x".repeat(9000),
                    ..Default::default()
                }
            )
            .unwrap_err()
            .code,
        "InvalidRequest"
    );
    // Malformed CVE rejected.
    assert_eq!(
        engine
            .store
            .create_finding(
                ws,
                NewFinding {
                    title: "Bad CVE".into(),
                    cve_ids: vec!["not-a-cve".into()],
                    ..Default::default()
                }
            )
            .unwrap_err()
            .code,
        "InvalidRequest"
    );
}

#[test]
fn invalid_update_rolls_back_and_leaves_finding_unchanged() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(&temp.path().join("store"));
    let ws = workspace(&engine);
    let finding = engine
        .store
        .create_finding(
            ws,
            NewFinding {
                title: "Stable".into(),
                severity: Severity::Low,
                ..Default::default()
            },
        )
        .unwrap();
    // An update with an invalid tag fails; nothing is partially applied.
    let err = engine
        .store
        .update_finding(
            ws,
            finding.id,
            FindingEdit {
                severity: Some(Severity::Critical),
                tags: Some(vec!["x".repeat(100)]),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert_eq!(err.code, "InvalidRequest");
    let reloaded = engine.store.snapshot(ws).unwrap().findings.remove(0);
    assert_eq!(reloaded.severity, Severity::Low); // unchanged
    assert_eq!(reloaded.title, "Stable");
}

#[test]
fn result_projection_reconstructs_typed_items_from_durable_state() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("store");
    let (ws, chain_id) = {
        let engine = open(&root);
        let (ws, snap) = seeded(&engine);
        let chain = snap.chains.first().expect("a chain").id;
        let projection = engine.store.result_projection(ws, chain).unwrap();
        assert_eq!(projection.chain_id, chain);
        assert!(
            !projection.items.is_empty(),
            "synthetic run produced results"
        );
        // Each item carries typed provenance a consumer can act on without stdout.
        for item in &projection.items {
            assert!(!item.asset_type.is_empty());
            assert!(!item.asset_identity.is_empty());
            assert!(!item.discovered_by.is_empty());
        }
        // When the durable observations carry evidence, the projection surfaces it (so
        // Create-Finding can prefill an evidence reference, never console text).
        if snap.observations.iter().any(|o| o.evidence_id.is_some()) {
            assert!(projection.items.iter().any(|i| i.evidence_id.is_some()));
        }
        engine.shutdown();
        (ws, chain)
    };
    // Projection reconstructs identically after restart (pure read model).
    let engine = open(&root);
    let after = engine.store.result_projection(ws, chain_id).unwrap();
    assert!(!after.items.is_empty());
}
