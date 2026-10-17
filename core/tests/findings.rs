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

#[test]
fn full_lifecycle_and_multiple_canonical_links_survive_restart() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("store");
    let engine = open(&root);
    let (ws, snap) = seeded(&engine);
    let primary = snap.assets[0].id;
    let additional = snap.assets[1].id;
    let evidence: Vec<_> = snap.evidence.iter().map(|e| e.id).collect();
    assert!(evidence.len() >= 2);
    let created = engine
        .store
        .create_finding(
            ws,
            NewFinding {
                title: "Manual offline assessment".into(),
                severity: Severity::High,
                confidence: FindingConfidence::Low,
                status: Some(FindingStatus::Draft),
                primary_asset_id: Some(primary),
                additional_asset_ids: vec![primary, additional, additional],
                evidence_ids: vec![evidence[0], evidence[1], evidence[0]],
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(created.affected_assets.len(), 2);
    assert_eq!(
        created
            .affected_assets
            .iter()
            .filter(|a| a.is_primary)
            .count(),
        1
    );
    assert_eq!(created.evidence_ids.len(), 2);
    assert!(engine
        .store
        .set_finding_status(ws, created.id, FindingStatus::Open, " ")
        .is_err());
    let mut updated = created;
    for status in [
        FindingStatus::Open,
        FindingStatus::FalsePositive,
        FindingStatus::Open,
        FindingStatus::Confirmed,
        FindingStatus::Resolved,
        FindingStatus::RetestPassed,
        FindingStatus::Open,
    ] {
        updated = engine
            .store
            .set_finding_status(ws, updated.id, status, "Offline analyst review.")
            .unwrap();
        assert_eq!(updated.severity, Severity::High);
        assert_eq!(updated.confidence, FindingConfidence::Low);
    }
    engine.shutdown();
    drop(engine);
    let reopened = open(&root);
    assert_eq!(reopened.store.snapshot(ws).unwrap().findings[0], updated);
}

#[test]
fn references_and_operations_fail_closed_across_workspaces_and_provider_mismatch() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(&temp.path().join("store"));
    let (ws, snap) = seeded(&engine);
    let other = workspace(&engine);
    let run = &snap.provider_runs[0];
    let finding = engine
        .store
        .create_finding(
            ws,
            NewFinding {
                title: "Reference checks".into(),
                ..Default::default()
            },
        )
        .unwrap();
    let events = engine.store.snapshot(ws).unwrap().last_sequence;
    for target in [ws, other] {
        let err = engine
            .store
            .create_finding(
                target,
                NewFinding {
                    title: "Untrusted source".into(),
                    source_run_id: Some(run.id),
                    source_provider: Some("different_provider".into()),
                    ..Default::default()
                },
            )
            .unwrap_err();
        assert_eq!(err.code, "InvalidRequest");
    }
    assert!(engine
        .store
        .update_finding(
            other,
            finding.id,
            FindingEdit {
                title: Some("wrong workspace".into()),
                ..Default::default()
            }
        )
        .is_err());
    assert!(engine
        .store
        .set_finding_status(
            other,
            finding.id,
            FindingStatus::Confirmed,
            "Wrong workspace"
        )
        .is_err());
    assert!(engine
        .store
        .link_finding_evidence(other, finding.id, snap.evidence[0].id)
        .is_err());
    assert!(engine
        .store
        .unlink_finding_evidence(other, finding.id, snap.evidence[0].id)
        .is_err());
    let result = engine.store.snapshot(ws).unwrap();
    assert_eq!(result.findings, vec![finding]);
    assert_eq!(result.last_sequence, events);
}

#[test]
fn malformed_enums_and_all_repeated_field_bounds_are_rejected() {
    use macsploit_core::findings::*;
    use macsploit_core::protocol::Request;
    use serde_json::json;
    for (key, value) in [
        ("severity", "UNKNOWN"),
        ("confidence", "CRITICAL"),
        ("status", "LOW"),
    ] {
        let mut new =
            json!({"title":"Fixture", "severity":"LOW", "confidence":"HIGH", "status":"OPEN"});
        new[key] = json!(value);
        assert!(serde_json::from_value::<Request>(json!({"protocol_version":1,"request_id":"bad-enum","method":"create_finding","params":{"workspace_id":Id::new_v4(),"finding":new}})).is_err());
    }
    let temp = tempfile::tempdir().unwrap();
    let engine = open(&temp.path().join("store"));
    let ws = workspace(&engine);
    for new in [
        NewFinding {
            title: "x".repeat(MAX_TITLE_BYTES + 1),
            ..Default::default()
        },
        NewFinding {
            title: "Fixture".into(),
            reproduction: "x".repeat(MAX_TEXT_BYTES + 1),
            ..Default::default()
        },
        NewFinding {
            title: "Fixture".into(),
            remediation: "x".repeat(MAX_TEXT_BYTES + 1),
            ..Default::default()
        },
        NewFinding {
            title: "Fixture".into(),
            tags: vec!["tag".into(); MAX_TAGS + 1],
            ..Default::default()
        },
        NewFinding {
            title: "Fixture".into(),
            cwe_ids: vec!["CWE-79".into(); MAX_IDS + 1],
            ..Default::default()
        },
        NewFinding {
            title: "Fixture".into(),
            cve_ids: vec!["CVE-2021-44228".into(); MAX_IDS + 1],
            ..Default::default()
        },
        NewFinding {
            title: "Fixture".into(),
            source_provider: Some("x".repeat(129)),
            ..Default::default()
        },
    ] {
        assert_eq!(
            engine.store.create_finding(ws, new).unwrap_err().code,
            "InvalidRequest"
        );
    }
    assert!(engine.store.snapshot(ws).unwrap().findings.is_empty());
}

#[test]
fn version_seven_upgrade_preserves_existing_recon_and_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("store");
    let engine = open(&root);
    let (ws, before) = seeded(&engine);
    let raw = engine
        .store
        .read_evidence(ws, before.evidence[0].id)
        .unwrap();
    let conn = engine.store.connect(ws).unwrap();
    conn.execute_batch("DROP TABLE finding_history; DROP TABLE finding_evidence; DROP TABLE finding_assets; DROP TABLE findings; PRAGMA user_version=7;").unwrap();
    drop(conn);
    engine.shutdown();
    drop(engine);
    let reopened = open(&root);
    let after = reopened.store.snapshot(ws).unwrap();
    assert_eq!(
        serde_json::to_value(before).unwrap(),
        serde_json::to_value(after).unwrap()
    );
    assert_eq!(
        raw,
        reopened
            .store
            .read_evidence(ws, reopened.store.snapshot(ws).unwrap().evidence[0].id)
            .unwrap()
    );
    let version: i64 = reopened
        .store
        .connect(ws)
        .unwrap()
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(version, 8);
}

#[test]
fn projection_is_exact_chain_read_only_and_distinguishes_context_from_relationships() {
    use macsploit_core::assets::{AssetType, Discovery};
    use macsploit_core::result::ResultItemKind;
    use serde_json::json;
    let temp = tempfile::tempdir().unwrap();
    let engine = open(&temp.path().join("store"));
    let (ws, snap) = seeded(&engine);
    let a = snap.chains[0].id;
    let original = engine.store.result_projection(ws, a).unwrap();
    let b = engine
        .start(ws, snap.targets[0].id, ChainKind::Synthetic, Value::Null)
        .unwrap();
    wait(&engine, ws);
    let second = engine.store.result_projection(ws, b.id).unwrap();
    assert_eq!(original, engine.store.result_projection(ws, a).unwrap());
    assert!(original.items.iter().all(|x| !second
        .items
        .iter()
        .any(|y| y.observation_id == x.observation_id)));
    assert!(original
        .items
        .iter()
        .any(|x| second.items.iter().any(|y| y.asset_id == x.asset_id)));
    assert!(original
        .items
        .iter()
        .any(|x| x.kind == ResultItemKind::RelationshipObservation));
    let run = &snap.provider_runs[0];
    let evidence = snap
        .evidence
        .iter()
        .find(|e| e.provider_run_id == run.id)
        .unwrap();
    engine
        .store
        .persist_discoveries(
            ws,
            run.id,
            evidence.id,
            "synthetic",
            &[Discovery {
                asset_type: AssetType::Website,
                value: "https://example.test/no-edge".into(),
                source: Some("example.test".into()),
                relationship: None,
                observation: None,
                metadata: json!({"status":200}),
            }],
        )
        .unwrap();
    let projected = engine.store.result_projection(ws, a).unwrap();
    assert_eq!(
        projected
            .items
            .iter()
            .find(|x| x.asset_identity == "https://example.test/no-edge")
            .unwrap()
            .kind,
        ResultItemKind::AssetObservation
    );
    let path = engine.store.directory(ws).join("workspace.sqlite");
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(projected, engine.store.result_projection(ws, a).unwrap());
    assert_eq!(bytes, std::fs::read(path).unwrap());
    let other = workspace(&engine);
    assert_eq!(
        engine.store.result_projection(other, a).unwrap_err().code,
        "InvalidRequest"
    );
    assert_eq!(
        engine
            .store
            .result_projection(ws, Id::new_v4())
            .unwrap_err()
            .code,
        "InvalidRequest"
    );
    let conn = engine.store.connect(ws).unwrap();
    conn.execute("DELETE FROM relationship_observations WHERE provider_run_id IN (SELECT id FROM provider_runs WHERE chain_id=?1)",[b.id.to_string()]).unwrap();
    conn.execute("DELETE FROM observations WHERE provider_run_id IN (SELECT id FROM provider_runs WHERE chain_id=?1)",[b.id.to_string()]).unwrap();
    assert!(engine
        .store
        .result_projection(ws, b.id)
        .unwrap()
        .items
        .is_empty());
    // Missing SQL tables must be DatabaseError, never misreported as an unknown chain.
    conn.execute("ALTER TABLE chain_runs RENAME TO unavailable_chains", [])
        .unwrap();
    assert_eq!(
        engine.store.result_projection(ws, a).unwrap_err().code,
        "DatabaseError"
    );
}

#[test]
fn projection_metadata_omission_and_record_budget_are_explicit() {
    use serde_json::json;
    let temp = tempfile::tempdir().unwrap();
    let engine = open(&temp.path().join("store"));
    let (ws, snap) = seeded(&engine);
    let chain = snap.chains[0].id;
    let conn = engine.store.connect(ws).unwrap();
    let large = json!({"fixture":"x".repeat(33*1024)}).to_string();
    conn.execute(
        "UPDATE observations SET metadata=?1 WHERE provider_run_id IS NOT NULL",
        [large],
    )
    .unwrap();
    let result = engine.store.result_projection(ws, chain).unwrap();
    assert!(result
        .items
        .iter()
        .all(|i| i.metadata_omitted && i.metadata.is_null()));
    conn.execute_batch("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<10001)
        INSERT INTO observations(id,workspace_id,asset_id,source_asset_id,provider_run_id,evidence_id,discovered_by,observed_value,timestamp,confidence,metadata)
        SELECT lower(hex(randomblob(16))),o.workspace_id,o.asset_id,o.source_asset_id,o.provider_run_id,o.evidence_id,o.discovered_by,o.observed_value,o.timestamp,o.confidence,NULL
        FROM n CROSS JOIN (SELECT * FROM observations WHERE provider_run_id IS NOT NULL LIMIT 1) o;").unwrap();
    assert_eq!(
        engine.store.result_projection(ws, chain).unwrap_err().code,
        "ResultsTooLarge"
    );
}

#[test]
fn malformed_stored_finding_data_is_never_silently_replaced() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(&temp.path().join("store"));
    let ws = workspace(&engine);
    let finding = engine
        .store
        .create_finding(
            ws,
            NewFinding {
                title: "Strict decoding".into(),
                ..Default::default()
            },
        )
        .unwrap();
    let conn = engine.store.connect(ws).unwrap();
    conn.execute(
        "UPDATE findings SET tags='{}' WHERE id=?1",
        [finding.id.to_string()],
    )
    .unwrap();
    assert_eq!(engine.store.snapshot(ws).unwrap_err().code, "DatabaseError");
    conn.execute(
        "UPDATE findings SET tags='[]',source_run_id='invalid-uuid' WHERE id=?1",
        [finding.id.to_string()],
    )
    .unwrap();
    assert_eq!(engine.store.snapshot(ws).unwrap_err().code, "DatabaseError");
}
