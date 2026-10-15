//! Milestone 6 / Issue #67 (implementation portion): end-to-end OSINT acceptance
//! across Username, Email, Phone, and Domain subjects, the explicit correlation
//! model, restart persistence, and failure semantics. Entirely offline: fake
//! provider executables and a static web transport; reserved/synthetic subjects only.

use macsploit_core::{
    assets::{AssetType, Id},
    correlation::{
        CorrelationBasis, CorrelationConfidence, CorrelationStatus, Proposal, ReviewDecision,
    },
    database::Store,
    dns::StaticDnsResolver,
    events::ChainStatus,
    orchestration::{ChainKind, Engine, Snapshot},
    process::ToolConfig,
    protocol::{self, Request},
    web::StaticWebTransport,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

const CT_URL: &str = "https://crt.sh/?q=%25.example.test&output=json";
const CT_BODY: &str = r#"[{"id":1,"common_name":"api.example.test","name_value":"api.example.test","not_before":"2025-01-01T00:00:00","not_after":"2099-01-01T00:00:00"}]"#;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures")
        .join(name)
        .canonicalize()
        .unwrap_or_else(|_| panic!("fixture {name} exists"))
}

fn tools() -> ToolConfig {
    let mut tools = ToolConfig::default();
    for (tool, file) in [
        ("sherlock", "fake-sherlock.sh"),
        ("socialscan", "fake-socialscan.sh"),
        ("phoneinfoga", "fake-phoneinfoga.sh"),
        ("theHarvester", "fake-theharvester.sh"),
    ] {
        tools.overrides.insert(tool.into(), fixture(file));
    }
    tools
}

fn open(root: &Path, tools: ToolConfig) -> Engine {
    Engine::open_with_web(
        Store::open(root).unwrap(),
        Duration::ZERO,
        tools,
        Arc::new(StaticDnsResolver::new()),
        Arc::new(StaticWebTransport::new().with_response(CT_URL, 200, &[], CT_BODY)),
    )
    .unwrap()
}

fn wait(engine: &Engine, ws: Id) -> Snapshot {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !engine.idle() {
        assert!(Instant::now() < deadline, "chain timed out");
        thread::sleep(Duration::from_millis(5));
    }
    engine.store.snapshot(ws).unwrap()
}

fn run(engine: &Engine, ws: Id, value: &str, kind: ChainKind, provider: &str) -> Snapshot {
    let target = engine.store.add_target(ws, value).unwrap();
    engine
        .start(ws, target.id, kind, json!({ "provider_id": provider }))
        .unwrap();
    wait(engine, ws)
}

fn asset_id(snap: &Snapshot, kind: AssetType, identity: &str) -> Id {
    snap.assets
        .iter()
        .find(|a| a.asset_type == kind && a.canonical_identity == identity)
        .unwrap_or_else(|| panic!("missing {kind:?} {identity}"))
        .id
}

/// An evidence-backed observation of the asset (provider output, not analyst entry).
fn evidenced_observation(snap: &Snapshot, asset: Id) -> Id {
    snap.observations
        .iter()
        .find(|o| o.asset_id == asset && o.evidence_id.is_some())
        .expect("evidence-backed observation")
        .id
}

fn analyst_observation(snap: &Snapshot, asset: Id) -> Option<Id> {
    snap.observations
        .iter()
        .find(|o| o.asset_id == asset && o.evidence_id.is_none())
        .map(|o| o.id)
}

#[test]
fn four_subject_types_correlate_only_explicitly_and_survive_restart() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("store");
    let (ws, correlation_id, before_assets) = {
        let engine = open(&root, tools());
        let ws = engine
            .store
            .create_workspace(
                "Acceptance",
                &["example.test".into(), "*.example.test".into()],
            )
            .unwrap()
            .id;
        run(
            &engine,
            ws,
            "@octo-synthetic",
            ChainKind::UsernameOsint,
            "sherlock",
        );
        run(
            &engine,
            ws,
            "researcher@example.test",
            ChainKind::EmailOsint,
            "socialscan",
        );
        run(
            &engine,
            ws,
            "+33 1 99 00 12 34",
            ChainKind::PhoneOsint,
            "phoneinfoga",
        );
        let domain = engine.store.add_target(ws, "example.test").unwrap();
        for provider in ["theharvester", "native_ct"] {
            engine
                .start(
                    ws,
                    domain.id,
                    ChainKind::DomainOsint,
                    json!({ "provider_id": provider }),
                )
                .unwrap();
            wait(&engine, ws);
        }
        let snap = engine.store.snapshot(ws).unwrap();
        assert_eq!(snap.chains.len(), 5);
        assert!(snap
            .chains
            .iter()
            .all(|c| matches!(c.status, ChainStatus::Completed | ChainStatus::Partial)));
        // Every subject type is represented canonically.
        let user = asset_id(&snap, AssetType::Username, "@octo-synthetic");
        let email = asset_id(&snap, AssetType::EmailAddress, "researcher@example.test");
        asset_id(&snap, AssetType::PhoneNumber, "+33199001234");
        asset_id(&snap, AssetType::Domain, "example.test");
        // Cross-provider agreement is explicit (one observation per provider run on
        // one canonical asset), and nothing is correlated automatically.
        let api = asset_id(&snap, AssetType::Subdomain, "api.example.test");
        let agreeing: BTreeSet<_> = snap
            .observations
            .iter()
            .filter(|o| o.asset_id == api)
            .map(|o| o.provider_run_id)
            .collect();
        assert_eq!(agreeing.len(), 2);
        assert!(snap.correlations.is_empty(), "no automatic correlation");

        let proposal = |observations: Vec<Id>, basis, confidence| Proposal {
            left_asset_id: user,
            right_asset_id: email,
            basis,
            confidence,
            rationale: "The public GitHub profile cited in evidence lists this address.".into(),
            observation_ids: observations,
        };
        let user_obs = evidenced_observation(&snap, user);
        let email_obs = evidenced_observation(&snap, email);
        // Refusals: one-sided evidence, analyst entries without evidence, a weak
        // signal claimed as strong, and self-correlation.
        for (bad, code) in [
            (
                proposal(
                    vec![user_obs],
                    CorrelationBasis::AnalystReview,
                    CorrelationConfidence::Medium,
                ),
                "InvalidRequest",
            ),
            (
                proposal(
                    vec![
                        user_obs,
                        analyst_observation(&snap, email).unwrap_or(email_obs),
                    ],
                    CorrelationBasis::SharedIdentifier,
                    CorrelationConfidence::High,
                ),
                "InvalidRequest",
            ),
        ] {
            assert_eq!(
                engine.store.propose_correlation(ws, bad).unwrap_err().code,
                code
            );
        }
        if let Some(analyst) = analyst_observation(&snap, email) {
            let err = engine
                .store
                .propose_correlation(
                    ws,
                    proposal(
                        vec![user_obs, analyst],
                        CorrelationBasis::AnalystReview,
                        CorrelationConfidence::Low,
                    ),
                )
                .unwrap_err();
            assert_eq!(err.code, "InvalidRequest");
        }
        let mut same = proposal(
            vec![user_obs],
            CorrelationBasis::AnalystReview,
            CorrelationConfidence::Low,
        );
        same.right_asset_id = user;
        assert_eq!(
            engine.store.propose_correlation(ws, same).unwrap_err().code,
            "InvalidRequest"
        );

        // A valid proposal through the protocol (the app's path).
        let response = protocol::handle(
            &engine,
            serde_json::from_value::<Request>(json!({
                "protocol_version": 1, "request_id": "corr-1", "method": "propose_correlation",
                "params": {"workspace_id": ws, "left_asset_id": email, "right_asset_id": user,
                           "basis": "shared_public_record", "confidence": "MEDIUM",
                           "rationale": "Profile lists the address.",
                           "observation_ids": [user_obs, email_obs]}
            }))
            .unwrap(),
        );
        assert!(response.error.is_none(), "{:?}", response.error);
        let created = response.result.unwrap();
        assert_eq!(created["status"], "PROPOSED");
        assert!(!created["evidence_ids"].as_array().unwrap().is_empty());
        let correlation_id: Id = serde_json::from_value(created["id"].clone()).unwrap();
        // A duplicate (either order) is refused; review the existing one instead.
        let dup = engine
            .store
            .propose_correlation(
                ws,
                proposal(
                    vec![user_obs, email_obs],
                    CorrelationBasis::AnalystReview,
                    CorrelationConfidence::Low,
                ),
            )
            .unwrap_err();
        assert_eq!(dup.code, "CorrelationExists");

        // Review lifecycle: confirm -> retract -> reopen; invalid transitions refused.
        let response = protocol::handle(
            &engine,
            serde_json::from_value::<Request>(json!({
                "protocol_version": 1, "request_id": "corr-2", "method": "review_correlation",
                "params": {"workspace_id": ws, "correlation_id": correlation_id,
                           "decision": "confirm", "note": "Checked the evidence."}
            }))
            .unwrap(),
        );
        assert!(response.error.is_none(), "{:?}", response.error);
        assert_eq!(response.result.unwrap()["status"], "CONFIRMED");
        assert_eq!(
            engine
                .store
                .review_correlation(ws, correlation_id, ReviewDecision::Confirm, "again")
                .unwrap_err()
                .code,
            "InvalidTransition"
        );
        engine
            .store
            .review_correlation(
                ws,
                correlation_id,
                ReviewDecision::Retract,
                "Profile changed hands.",
            )
            .unwrap();
        let c = engine
            .store
            .review_correlation(
                ws,
                correlation_id,
                ReviewDecision::Reopen,
                "New evidence to assess.",
            )
            .unwrap();
        assert_eq!(c.status, CorrelationStatus::Proposed);
        assert_eq!(c.reviews.len(), 4, "append-only review log");
        assert!(engine
            .store
            .review_correlation(ws, correlation_id, ReviewDecision::Reject, "   ")
            .is_err());

        let after = engine.store.snapshot(ws).unwrap();
        // Correlation never touched assets, observations, or relationships.
        assert_eq!(json!(after.assets), json!(snap.assets));
        assert_eq!(after.observations.len(), snap.observations.len());
        assert_eq!(after.relationships.len(), snap.relationships.len());
        engine.shutdown();
        (ws, correlation_id, snap.assets)
    };

    // Restart: everything, including correlation provenance, is durable.
    let engine = open(&root, tools());
    let snap = engine.store.snapshot(ws).unwrap();
    assert_eq!(
        json!(snap.assets),
        json!(before_assets),
        "prior metadata not overwritten"
    );
    let correlation = snap
        .correlations
        .iter()
        .find(|c| c.id == correlation_id)
        .unwrap();
    assert_eq!(correlation.status, CorrelationStatus::Proposed);
    assert_eq!(correlation.basis, CorrelationBasis::SharedPublicRecord);
    assert_eq!(correlation.confidence, CorrelationConfidence::Medium);
    assert_eq!(
        correlation
            .reviews
            .iter()
            .map(|r| r.to_status)
            .collect::<Vec<_>>(),
        [
            CorrelationStatus::Proposed,
            CorrelationStatus::Confirmed,
            CorrelationStatus::Retracted,
            CorrelationStatus::Proposed
        ]
    );
    for evidence in &correlation.evidence_ids {
        engine.store.read_evidence(ws, *evidence).unwrap();
    }
    // Repeated runs remain distinguishable after restart.
    let runs: BTreeSet<_> = snap.provider_runs.iter().map(|r| r.id).collect();
    assert_eq!(runs.len(), 5);
    assert!(snap.events.iter().any(|e| matches!(
        e.event_type,
        macsploit_core::events::EventType::CorrelationReviewed
    )));
}

fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, body).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

/// (subject, workflow, provider, theHarvester override, expected status, expected code)
type FailureCase<'a> = (
    &'a str,
    ChainKind,
    &'a str,
    Option<PathBuf>,
    ChainStatus,
    Option<&'a str>,
);

/// Failure semantics: zero results, partial, error, malformed, missing, and
/// unsupported versions are distinct outcomes, and any run that started keeps its
/// evidence. (Cancellation and timeouts are covered per provider in
/// osint_domain.rs, osint_phone.rs, and osint_username_wave.rs.)
#[test]
fn failure_semantics_are_distinct_and_keep_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let mut configured = tools();
    let old = script(
        temp.path(),
        "old-harvester",
        "#!/bin/sh\necho '* theHarvester 3.2.0 *'\nexit 0\n",
    );
    let cases: Vec<FailureCase> = vec![
        (
            "empty.test",
            ChainKind::DomainOsint,
            "theharvester",
            None,
            ChainStatus::Completed,
            None,
        ),
        (
            "+12025550143",
            ChainKind::PhoneOsint,
            "phoneinfoga",
            None,
            ChainStatus::Partial,
            None,
        ),
        (
            "failing.test",
            ChainKind::DomainOsint,
            "theharvester",
            None,
            ChainStatus::Failed,
            Some("ProviderFailure"),
        ),
        (
            "malformed.test",
            ChainKind::DomainOsint,
            "theharvester",
            None,
            ChainStatus::Failed,
            Some("ProviderFailure"),
        ),
        (
            "example.test",
            ChainKind::DomainOsint,
            "theharvester",
            Some(temp.path().join("absent")),
            ChainStatus::Failed,
            Some("ProviderMissing"),
        ),
        (
            "example.test",
            ChainKind::DomainOsint,
            "theharvester",
            Some(old),
            ChainStatus::Failed,
            Some("ProviderUnsupported"),
        ),
    ];
    for (value, kind, provider, harvester, status, code) in cases {
        if let Some(path) = harvester {
            configured.overrides.insert("theHarvester".into(), path);
        } else {
            configured
                .overrides
                .insert("theHarvester".into(), fixture("fake-theharvester.sh"));
        }
        let dir = tempfile::tempdir().unwrap();
        let engine = open(dir.path(), configured.clone());
        let ws = engine
            .store
            .create_workspace(
                "Failures",
                &[
                    "example.test".into(),
                    "empty.test".into(),
                    "failing.test".into(),
                    "malformed.test".into(),
                ],
            )
            .unwrap()
            .id;
        let snap = run(&engine, ws, value, kind, provider);
        let chain = &snap.chains[0];
        assert_eq!(chain.status, status, "{value} {provider}");
        assert_eq!(chain.error_code.as_deref(), code, "{value} {provider}");
        // A run that started keeps evidence; a missing/unsupported tool never starts.
        let started = !matches!(code, Some("ProviderMissing" | "ProviderUnsupported"));
        assert_eq!(!snap.evidence.is_empty(), started, "{value} {provider}");
        for evidence in &snap.evidence {
            engine.store.read_evidence(ws, evidence.id).unwrap();
        }
    }
}

#[test]
fn snapshots_from_before_correlations_still_decode() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(temp.path(), tools());
    let ws = engine.store.create_workspace("Legacy", &[]).unwrap().id;
    let mut value = serde_json::to_value(engine.store.snapshot(ws).unwrap()).unwrap();
    value.as_object_mut().unwrap().remove("correlations");
    let decoded: Snapshot = serde_json::from_value::<Value>(value)
        .and_then(serde_json::from_value)
        .unwrap();
    assert!(decoded.correlations.is_empty());
}
