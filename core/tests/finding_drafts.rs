//! Deterministic Finding drafts (Issue #79 + Level 1 of #81), offline. A synthetic chain
//! produces real durable Asset/Observation/Evidence/provider-run records; `draft_finding`
//! then builds a typed, non-persisted draft from a validated selection of those records.
//! No network, no scanners, no console parsing.

use macsploit_core::{
    assets::Id,
    database::Store,
    dns::StaticDnsResolver,
    draft::{DraftContext, DraftKind, MAX_DRAFT_OBSERVATIONS},
    findings::{FindingConfidence, FindingStatus, Severity, MAX_AFFECTED_ASSETS},
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
        .create_workspace("Drafts", &["example.test".into(), "*.example.test".into()])
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

/// Observation ids that belong to a chain's provider runs — the same run-scoped set the
/// result projection (and therefore the UI selection) would offer.
fn run_observation_ids(snap: &Snapshot, chain: Id) -> Vec<Id> {
    snap.observations
        .iter()
        .filter(|o| {
            o.provider_run_id.is_some_and(|r| {
                snap.provider_runs
                    .iter()
                    .any(|p| p.id == r && p.chain_id == chain)
            })
        })
        .map(|o| o.id)
        .collect()
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

#[test]
fn one_result_builds_a_factual_generic_draft_that_persists_and_survives_restart() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("store");
    let (ws, finding_id) = {
        let engine = open(&root);
        let (ws, snap) = seeded(&engine);
        let chain = snap.chains[0].id;
        let obs = snap
            .observations
            .iter()
            .find(|o| o.evidence_id.is_some() && o.provider_run_id.is_some())
            .expect("an evidence-backed observation");

        let draft = engine
            .store
            .draft_finding(
                ws,
                DraftContext {
                    run_id: Some(chain),
                    observation_ids: vec![obs.id],
                    ..Default::default()
                },
            )
            .unwrap();

        // Generic reconnaissance drafts are factual and informational — nothing invented.
        assert_eq!(draft.kind, DraftKind::GenericObservation);
        assert_eq!(draft.severity, Severity::Informational);
        assert_eq!(draft.confidence, FindingConfidence::Low);
        assert_eq!(draft.suggested_status, FindingStatus::Draft);
        assert!(draft.remediation.is_empty());
        assert!(draft.cve_ids.is_empty() && draft.cwe_ids.is_empty());
        assert!(!draft.title.is_empty() && !draft.description.is_empty());
        assert!(!draft.provenance.is_empty());

        // Durable references and exact provenance.
        assert_eq!(draft.primary_asset_id, Some(obs.asset_id));
        assert!(draft
            .affected_assets
            .iter()
            .any(|a| a.asset_id == obs.asset_id && a.is_primary));
        assert!(draft
            .evidence
            .iter()
            .any(|e| Some(e.evidence_id) == obs.evidence_id));
        assert_eq!(draft.source_run_id, obs.provider_run_id);
        assert!(draft.source_provider.is_some());

        // Drafting creates no Finding row.
        assert!(engine.store.snapshot(ws).unwrap().findings.is_empty());

        // Create from the (unedited) draft through the ordinary transactional path.
        let created = engine
            .store
            .create_finding(ws, draft.to_new_finding())
            .unwrap();
        assert_eq!(created.affected_assets.len(), 1);
        assert!(created.affected_assets[0].is_primary);
        assert_eq!(created.affected_assets[0].asset_id, obs.asset_id);
        assert_eq!(created.evidence_ids, vec![obs.evidence_id.unwrap()]);
        assert_eq!(created.source_run_id, obs.provider_run_id);
        assert_eq!(created.severity, Severity::Informational);
        engine.shutdown();
        (ws, created.id)
    };

    // The created finding and its references survive restart.
    let engine = open(&root);
    let snap = engine.store.snapshot(ws).unwrap();
    assert_eq!(snap.findings.len(), 1);
    assert_eq!(snap.findings[0].id, finding_id);
    assert_eq!(snap.findings[0].affected_assets.len(), 1);
    assert_eq!(snap.findings[0].evidence_ids.len(), 1);
}

#[test]
fn selected_results_and_assets_combine_dedupe_and_honor_explicit_primary() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(&temp.path().join("store"));
    let (ws, snap) = seeded(&engine);
    let chain = snap.chains[0].id;
    // Every run-scoped observation, plus a duplicate to prove de-duplication.
    let mut observation_ids = run_observation_ids(&snap, chain);
    assert!(observation_ids.len() >= 2);
    observation_ids.push(observation_ids[0]);
    let distinct_assets: Vec<Id> = {
        let mut v: Vec<Id> = Vec::new();
        for o in snap
            .observations
            .iter()
            .filter(|o| observation_ids.contains(&o.id))
        {
            if !v.contains(&o.asset_id) {
                v.push(o.asset_id);
            }
        }
        v
    };
    assert!(
        distinct_assets.len() >= 2,
        "synthetic run touches several assets"
    );
    let chosen_primary = distinct_assets[1];

    let draft = engine
        .store
        .draft_finding(
            ws,
            DraftContext {
                run_id: Some(chain),
                observation_ids,
                asset_ids: vec![distinct_assets[0], distinct_assets[0]], // duplicate
                evidence_ids: vec![],
                primary_asset_id: Some(chosen_primary),
            },
        )
        .unwrap();

    // Assets are de-duplicated; the explicit primary is honored (exactly one).
    assert_eq!(
        draft.affected_assets.len(),
        distinct_assets.len(),
        "each affected asset appears once regardless of how many observations referenced it"
    );
    assert_eq!(draft.primary_asset_id, Some(chosen_primary));
    assert_eq!(
        draft
            .affected_assets
            .iter()
            .filter(|a| a.is_primary)
            .count(),
        1
    );
    // Evidence references are de-duplicated too.
    let mut seen = std::collections::HashSet::new();
    assert!(draft.evidence.iter().all(|e| seen.insert(e.evidence_id)));
    // Several observations from one chain still share one provider run or none — if a
    // single run, the source is attributed; otherwise it stays unattributed (never wrong).
    if let Some(run) = draft.source_run_id {
        assert!(snap.provider_runs.iter().any(|r| r.id == run));
    }

    // The combined draft persists as a real multi-asset finding.
    let created = engine
        .store
        .create_finding(ws, draft.to_new_finding())
        .unwrap();
    assert_eq!(created.affected_assets.len(), distinct_assets.len());
    assert!(created
        .affected_assets
        .iter()
        .any(|a| a.asset_id == chosen_primary && a.is_primary));
}

#[test]
fn cross_workspace_wrong_run_and_empty_selections_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(&temp.path().join("store"));
    let (ws, snap) = seeded(&engine);
    let chain_a = snap.chains[0].id;

    // A second chain in the same workspace, with its own observations.
    let run_b = engine
        .start(ws, snap.targets[0].id, ChainKind::Synthetic, Value::Null)
        .unwrap();
    let snap = wait(&engine, ws);
    let obs_in_b = snap
        .observations
        .iter()
        .find(|o| {
            o.provider_run_id.is_some_and(|r| {
                snap.provider_runs
                    .iter()
                    .any(|p| p.id == r && p.chain_id == run_b.id)
            })
        })
        .expect("an observation produced by chain B");

    // A result from chain B cannot be drafted under chain A (wrong run).
    assert_eq!(
        engine
            .store
            .draft_finding(
                ws,
                DraftContext {
                    run_id: Some(chain_a),
                    observation_ids: vec![obs_in_b.id],
                    ..Default::default()
                },
            )
            .unwrap_err()
            .code,
        "InvalidRequest"
    );

    // Empty selection is refused rather than drafting from nothing.
    assert_eq!(
        engine
            .store
            .draft_finding(ws, DraftContext::default())
            .unwrap_err()
            .code,
        "InvalidRequest"
    );

    // A primary asset not in the selected set is refused.
    let a_obs = snap
        .observations
        .iter()
        .find(|o| {
            snap.provider_runs
                .iter()
                .any(|p| p.id == o.provider_run_id.unwrap_or(Id::new_v4()) && p.chain_id == chain_a)
        })
        .expect("an observation from chain A");
    assert_eq!(
        engine
            .store
            .draft_finding(
                ws,
                DraftContext {
                    observation_ids: vec![a_obs.id],
                    primary_asset_id: Some(Id::new_v4()),
                    ..Default::default()
                },
            )
            .unwrap_err()
            .code,
        "InvalidRequest"
    );

    // A separate workspace cannot reference the first workspace's assets/evidence/results.
    let other = engine
        .store
        .create_workspace("Other", &["example.test".into()])
        .unwrap()
        .id;
    assert_eq!(
        engine
            .store
            .draft_finding(
                other,
                DraftContext {
                    asset_ids: vec![snap.assets[0].id],
                    ..Default::default()
                },
            )
            .unwrap_err()
            .code,
        "AssetNotFound"
    );
    assert_eq!(
        engine
            .store
            .draft_finding(
                other,
                DraftContext {
                    evidence_ids: vec![snap.evidence[0].id],
                    ..Default::default()
                },
            )
            .unwrap_err()
            .code,
        "InvalidRequest"
    );
    assert_eq!(
        engine
            .store
            .draft_finding(
                other,
                DraftContext {
                    observation_ids: vec![a_obs.id],
                    ..Default::default()
                },
            )
            .unwrap_err()
            .code,
        "InvalidRequest"
    );
}

#[test]
fn oversized_selections_are_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(&temp.path().join("store"));
    let ws = workspace(&engine);
    // Too many results (length is bounded before any lookup).
    let many: Vec<Id> = (0..=MAX_DRAFT_OBSERVATIONS).map(|_| Id::new_v4()).collect();
    assert_eq!(
        engine
            .store
            .draft_finding(
                ws,
                DraftContext {
                    observation_ids: many,
                    ..Default::default()
                },
            )
            .unwrap_err()
            .code,
        "InvalidRequest"
    );
    // Too many assets.
    let assets: Vec<Id> = (0..=MAX_AFFECTED_ASSETS).map(|_| Id::new_v4()).collect();
    assert_eq!(
        engine
            .store
            .draft_finding(
                ws,
                DraftContext {
                    asset_ids: assets,
                    ..Default::default()
                },
            )
            .unwrap_err()
            .code,
        "InvalidRequest"
    );
}

#[test]
fn drafting_is_read_only_and_deterministic_across_restart() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("store");
    let (ws, chain, observation_ids, expected) = {
        let engine = open(&root);
        let (ws, snap) = seeded(&engine);
        let chain = snap.chains[0].id;
        let observation_ids: Vec<Id> = run_observation_ids(&snap, chain)
            .into_iter()
            .take(3)
            .collect();
        let ctx = DraftContext {
            run_id: Some(chain),
            observation_ids: observation_ids.clone(),
            ..Default::default()
        };
        let first = engine.store.draft_finding(ws, ctx.clone()).unwrap();
        // Same inputs → identical draft (no console/stdout, no hidden state).
        assert_eq!(first, engine.store.draft_finding(ws, ctx).unwrap());
        // Drafting wrote nothing.
        assert!(engine.store.snapshot(ws).unwrap().findings.is_empty());
        engine.shutdown();
        (ws, chain, observation_ids, first)
    };
    // Reconstructs identically from committed state after a restart.
    let engine = open(&root);
    let after = engine
        .store
        .draft_finding(
            ws,
            DraftContext {
                run_id: Some(chain),
                observation_ids,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(after, expected);
    assert!(engine.store.snapshot(ws).unwrap().findings.is_empty());
}
