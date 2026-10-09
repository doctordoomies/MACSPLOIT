use macsploit_core::{
    assets::{AssetType, Discovery, Id, RelationshipType},
    database::Store,
    events::{ChainStatus, TaskStatus},
    orchestration::{ChainKind, Engine, Snapshot},
};
use serde_json::json;
use std::{
    thread,
    time::{Duration, Instant},
};

fn setup() -> (tempfile::TempDir, Engine, Id, Id) {
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::open(Store::open(temp.path()).unwrap(), Duration::ZERO).unwrap();
    let workspace = engine
        .store
        .create_workspace(
            "Test Assessment",
            &[
                "example.test".into(),
                "*.example.test".into(),
                "192.0.2.0/24".into(),
            ],
        )
        .unwrap();
    let target = engine
        .store
        .add_target(workspace.id, "example.test")
        .unwrap();
    (temp, engine, workspace.id, target.id)
}

fn wait(engine: &Engine, workspace: Id) -> Snapshot {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !engine.idle() {
        assert!(Instant::now() < deadline, "chain timed out");
        thread::sleep(Duration::from_millis(5));
    }
    engine.store.snapshot(workspace).unwrap()
}

#[test]
fn complete_vertical_slice_persists_graph_events_evidence_and_restart() {
    let (temp, engine, workspace, target) = setup();
    let cursor = engine.store.snapshot(workspace).unwrap().last_sequence;
    let chain = engine
        .start(
            workspace,
            target,
            ChainKind::Synthetic,
            serde_json::Value::Null,
        )
        .unwrap();
    let snapshot = wait(&engine, workspace);
    assert_eq!(snapshot.chains[0].id, chain.id);
    assert_eq!(snapshot.chains[0].status, ChainStatus::Completed);
    assert_eq!(snapshot.assets.len(), 11);
    assert_eq!(snapshot.relationships.len(), 10);
    let identity = |id| {
        snapshot
            .assets
            .iter()
            .find(|a| a.id == id)
            .unwrap()
            .canonical_identity
            .as_str()
    };
    let actual: std::collections::BTreeSet<_> = snapshot
        .relationships
        .iter()
        .map(|edge| {
            (
                identity(edge.source_asset_id),
                identity(edge.destination_asset_id),
                macsploit_core::database::encoded(&edge.relationship_type),
            )
        })
        .collect();
    let expected = [
        ("example.test", "api.example.test", "has_subdomain"),
        ("example.test", "dev.example.test", "has_subdomain"),
        ("api.example.test", "192.0.2.10", "resolves_to"),
        ("dev.example.test", "192.0.2.11", "resolves_to"),
        ("192.0.2.10", "192.0.2.10/tcp/443", "exposes"),
        ("192.0.2.11", "192.0.2.11/tcp/22", "exposes"),
        ("192.0.2.11", "192.0.2.11/tcp/443", "exposes"),
        ("192.0.2.10/tcp/443", "192.0.2.10/tcp/443/https", "serves"),
        ("192.0.2.11/tcp/22", "192.0.2.11/tcp/22/ssh", "serves"),
        ("192.0.2.11/tcp/443", "192.0.2.11/tcp/443/https", "serves"),
    ]
    .into_iter()
    .map(|(source, destination, kind)| (source, destination, kind.to_owned()))
    .collect();
    assert_eq!(actual, expected);
    assert_eq!(snapshot.evidence.len(), 3);
    assert_eq!(snapshot.provider_runs.len(), 3);
    assert!(snapshot
        .tasks
        .iter()
        .all(|t| t.status == TaskStatus::Completed));
    assert!(snapshot
        .stages
        .iter()
        .all(|s| s.status == TaskStatus::Completed));
    assert!(snapshot
        .provider_runs
        .iter()
        .all(|r| r.raw_output_reference.is_some() && r.exit_status == Some(0)));
    for evidence in &snapshot.evidence {
        let raw = engine.store.read_evidence(workspace, evidence.id).unwrap();
        assert_eq!(
            macsploit_core::evidence::digest(raw.as_bytes()),
            evidence.sha256
        );
        // Evidence is now a provider envelope; the synthetic output is preserved
        // verbatim inside its `stdout` field.
        let envelope = serde_json::from_str::<serde_json::Value>(&raw).unwrap();
        assert_eq!(envelope["offline"], true);
        assert_eq!(envelope["provider"], "synthetic");
        let stdout = envelope["stdout"].as_str().unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(stdout).unwrap()["synthetic"],
            true
        );
    }
    let replay = engine.store.events_after(workspace, cursor).unwrap();
    assert!(replay.len() > 30);
    assert!(replay.iter().all(|e| e.sequence > cursor));
    assert!(replay.windows(2).all(|w| w[0].sequence < w[1].sequence));
    drop(engine);
    let reopened = Engine::open(Store::open(temp.path()).unwrap(), Duration::ZERO).unwrap();
    let persisted = reopened.store.snapshot(workspace).unwrap();
    assert_eq!(
        serde_json::to_value(&snapshot).unwrap(),
        serde_json::to_value(&persisted).unwrap()
    );
}

#[test]
fn duplicate_discoveries_and_repeat_runs_preserve_provenance() {
    let (_temp, engine, workspace, target) = setup();
    engine
        .start(
            workspace,
            target,
            ChainKind::Synthetic,
            serde_json::Value::Null,
        )
        .unwrap();
    let first = wait(&engine, workspace);
    let api = first
        .assets
        .iter()
        .find(|a| a.canonical_identity == "api.example.test")
        .unwrap();
    assert_eq!(
        first
            .observations
            .iter()
            .filter(|o| o.asset_id == api.id)
            .count(),
        3
    );
    engine
        .start(
            workspace,
            target,
            ChainKind::Synthetic,
            serde_json::Value::Null,
        )
        .unwrap();
    let second = wait(&engine, workspace);
    assert_eq!(second.assets.len(), 11);
    assert_eq!(second.relationships.len(), 10);
    assert_eq!(
        second
            .observations
            .iter()
            .filter(|o| o.asset_id == api.id)
            .count(),
        6
    );
    assert_eq!(second.evidence.len(), 6);
}

#[test]
fn repeated_url_observations_keep_run_specific_metadata_across_restart() {
    let (temp, engine, workspace, target) = setup();

    engine
        .start(
            workspace,
            target,
            ChainKind::Synthetic,
            serde_json::Value::Null,
        )
        .unwrap();
    let first = wait(&engine, workspace);
    let run_a = first.provider_runs[0].id;
    let evidence_a = first
        .evidence
        .iter()
        .find(|e| e.provider_run_id == run_a)
        .unwrap()
        .id;

    let url = "https://example.test/admin";
    engine
        .store
        .persist_discoveries(
            workspace,
            run_a,
            evidence_a,
            "fixture",
            &[Discovery {
                asset_type: AssetType::URL,
                value: url.into(),
                source: None,
                relationship: None,
                observation: None,
                metadata: json!({
                    "tool": "ffuf",
                    "status": 200,
                    "content_length": 42,
                    "redirect": null
                }),
            }],
        )
        .unwrap();

    engine
        .start(
            workspace,
            target,
            ChainKind::Synthetic,
            serde_json::Value::Null,
        )
        .unwrap();
    let second = wait(&engine, workspace);
    let run_b = second
        .provider_runs
        .iter()
        .find(|run| !first.provider_runs.iter().any(|old| old.id == run.id))
        .unwrap()
        .id;
    let evidence_b = second
        .evidence
        .iter()
        .find(|e| e.provider_run_id == run_b)
        .unwrap()
        .id;

    engine
        .store
        .persist_discoveries(
            workspace,
            run_b,
            evidence_b,
            "fixture",
            &[Discovery {
                asset_type: AssetType::URL,
                value: url.into(),
                source: None,
                relationship: None,
                observation: None,
                metadata: json!({
                    "tool": "ffuf",
                    "status": 403,
                    "content_length": 7,
                    "redirect": "/login"
                }),
            }],
        )
        .unwrap();

    let current = engine.store.snapshot(workspace).unwrap();
    let url_asset = current
        .assets
        .iter()
        .find(|asset| asset.canonical_identity == url)
        .unwrap();
    assert_eq!(
        current
            .assets
            .iter()
            .filter(|asset| asset.canonical_identity == url)
            .count(),
        1
    );
    assert_eq!(url_asset.metadata["status"], 200);
    assert_eq!(url_asset.metadata["in_scope"], true);

    let observation_a = current
        .observations
        .iter()
        .find(|o| o.asset_id == url_asset.id && o.provider_run_id == Some(run_a))
        .unwrap();
    let observation_b = current
        .observations
        .iter()
        .find(|o| o.asset_id == url_asset.id && o.provider_run_id == Some(run_b))
        .unwrap();
    assert_eq!(observation_a.metadata.as_ref().unwrap()["status"], 200);
    assert_eq!(observation_a.metadata.as_ref().unwrap()["content_length"], 42);
    assert_eq!(observation_b.metadata.as_ref().unwrap()["status"], 403);
    assert_eq!(observation_b.metadata.as_ref().unwrap()["content_length"], 7);
    assert_eq!(observation_b.metadata.as_ref().unwrap()["redirect"], "/login");
    assert!(observation_a.metadata.as_ref().unwrap().get("in_scope").is_none());
    assert!(observation_b.metadata.as_ref().unwrap().get("in_scope").is_none());

    drop(engine);
    let reopened = Engine::open(Store::open(temp.path()).unwrap(), Duration::ZERO).unwrap();
    let persisted = reopened.store.snapshot(workspace).unwrap();
    let persisted_url = persisted
        .assets
        .iter()
        .find(|asset| asset.canonical_identity == url)
        .unwrap();
    let persisted_observations: Vec<_> = persisted
        .observations
        .iter()
        .filter(|o| o.asset_id == persisted_url.id)
        .collect();
    assert_eq!(persisted_observations.len(), 2);
    assert!(persisted_observations
        .iter()
        .any(|o| o.metadata.as_ref().unwrap()["status"] == 200));
    assert!(persisted_observations
        .iter()
        .any(|o| o.metadata.as_ref().unwrap()["status"] == 403));
}

#[test]
fn discovery_metadata_is_object_only_and_bounded() {
    let (_temp, engine, workspace, target) = setup();
    engine
        .start(
            workspace,
            target,
            ChainKind::Synthetic,
            serde_json::Value::Null,
        )
        .unwrap();
    let before = wait(&engine, workspace);
    let run = before.provider_runs[0].id;
    let evidence = before
        .evidence
        .iter()
        .find(|e| e.provider_run_id == run)
        .unwrap()
        .id;

    let non_object = Discovery {
        asset_type: AssetType::URL,
        value: "https://example.test/non-object".into(),
        source: None,
        relationship: None,
        observation: None,
        metadata: json!(["not", "an", "object"]),
    };
    assert_eq!(
        engine
            .store
            .persist_discoveries(workspace, run, evidence, "fixture", &[non_object])
            .unwrap_err()
            .code,
        "ProviderFailure"
    );

    let oversized = Discovery {
        asset_type: AssetType::URL,
        value: "https://example.test/oversized".into(),
        source: None,
        relationship: None,
        observation: None,
        metadata: json!({"summary": "x".repeat(20 * 1024)}),
    };
    assert_eq!(
        engine
            .store
            .persist_discoveries(workspace, run, evidence, "fixture", &[oversized])
            .unwrap_err()
            .code,
        "ProviderFailure"
    );

    let after = engine.store.snapshot(workspace).unwrap();
    assert_eq!(
        serde_json::to_value(before).unwrap(),
        serde_json::to_value(after).unwrap()
    );
}

#[test]
fn chain_results_are_scoped_to_one_run_and_preserve_typed_provenance() {
    let (temp, engine, workspace, target) = setup();
    let first_chain = engine
        .start(
            workspace,
            target,
            ChainKind::Synthetic,
            serde_json::Value::Null,
        )
        .unwrap();
    let first_snapshot = wait(&engine, workspace);
    let first_results = engine
        .store
        .chain_results(workspace, first_chain.id)
        .unwrap();

    assert_eq!(first_results.chain.id, first_chain.id);
    assert_eq!(first_results.target.id, target);
    assert_eq!(first_results.provider_runs.len(), 3);
    assert_eq!(first_results.evidence.len(), 3);
    assert_eq!(first_results.relationships.len(), 10);
    assert_eq!(first_results.relationship_observations.len(), 10);

    let provider_ids: std::collections::HashSet<_> = first_results
        .provider_runs
        .iter()
        .map(|run| run.id)
        .collect();
    let evidence_ids: std::collections::HashSet<_> = first_results
        .evidence
        .iter()
        .map(|evidence| evidence.id)
        .collect();
    let relationship_ids: std::collections::HashSet<_> = first_results
        .relationships
        .iter()
        .map(|relationship| relationship.id)
        .collect();
    let asset_ids: std::collections::HashSet<_> =
        first_results.assets.iter().map(|asset| asset.id).collect();

    assert!(first_results.observations.iter().all(|observation| {
        observation
            .provider_run_id
            .is_some_and(|run| provider_ids.contains(&run))
            && observation
                .evidence_id
                .is_some_and(|evidence| evidence_ids.contains(&evidence))
            && asset_ids.contains(&observation.asset_id)
    }));
    assert!(first_results
        .relationship_observations
        .iter()
        .all(|provenance| {
            provider_ids.contains(&provenance.provider_run_id)
                && evidence_ids.contains(&provenance.evidence_id)
                && relationship_ids.contains(&provenance.relationship_id)
        }));
    assert!(first_results.relationships.iter().all(|relationship| {
        asset_ids.contains(&relationship.source_asset_id)
            && asset_ids.contains(&relationship.destination_asset_id)
    }));

    let second_chain = engine
        .start(
            workspace,
            target,
            ChainKind::Synthetic,
            serde_json::Value::Null,
        )
        .unwrap();
    let second_snapshot = wait(&engine, workspace);
    assert!(second_snapshot
        .provider_runs
        .iter()
        .any(|run| run.chain_id == second_chain.id));

    let first_after_second = engine
        .store
        .chain_results(workspace, first_chain.id)
        .unwrap();
    assert!(first_after_second
        .provider_runs
        .iter()
        .all(|run| run.chain_id == first_chain.id));
    assert_eq!(first_after_second.provider_runs.len(), 3);
    assert_eq!(first_after_second.evidence.len(), 3);
    assert_eq!(
        first_after_second.observations.len(),
        first_results.observations.len()
    );
    assert_eq!(
        first_after_second.relationship_observations.len(),
        first_results.relationship_observations.len()
    );

    drop(engine);
    let reopened = Engine::open(Store::open(temp.path()).unwrap(), Duration::ZERO).unwrap();
    let persisted = reopened
        .store
        .chain_results(workspace, first_chain.id)
        .unwrap();
    assert_eq!(
        serde_json::to_value(first_after_second).unwrap(),
        serde_json::to_value(persisted).unwrap()
    );

    let other = reopened
        .store
        .create_workspace("Other", &["example.test".into()])
        .unwrap();
    assert_eq!(
        reopened
            .store
            .chain_results(other.id, first_chain.id)
            .unwrap_err()
            .code,
        "ChainNotFound"
    );

    // The ordinary snapshot still contains both chains; chain_results is the scoped view.
    assert!(first_snapshot.chains.len() < second_snapshot.chains.len());
}

#[test]
fn missing_scope_prevents_dispatch_and_scope_limits_downstream_work() {
    let (_temp, engine, _, _) = setup();
    let denied = engine.store.create_workspace("No Scope", &[]).unwrap();
    let target = engine.store.add_target(denied.id, "example.test").unwrap();
    assert_eq!(
        engine
            .start(
                denied.id,
                target.id,
                ChainKind::Synthetic,
                serde_json::Value::Null
            )
            .unwrap_err()
            .code,
        "ScopeViolation"
    );
    let limited = engine
        .store
        .create_workspace("Root only", &["example.test".into()])
        .unwrap();
    let target = engine.store.add_target(limited.id, "example.test").unwrap();
    engine
        .start(
            limited.id,
            target.id,
            ChainKind::Synthetic,
            serde_json::Value::Null,
        )
        .unwrap();
    let snapshot = wait(&engine, limited.id);
    assert_eq!(snapshot.assets.len(), 3); // passive out-of-scope subdomains remain visible
    assert!(snapshot
        .assets
        .iter()
        .all(|a| a.asset_type != AssetType::IPAddress));
    assert!(snapshot
        .assets
        .iter()
        .filter(|a| a.asset_type == AssetType::Subdomain)
        .all(|a| a.metadata["in_scope"] == false));
}

#[test]
fn evidence_tampering_and_path_traversal_are_rejected() {
    let (_temp, engine, workspace, target) = setup();
    engine
        .start(
            workspace,
            target,
            ChainKind::Synthetic,
            serde_json::Value::Null,
        )
        .unwrap();
    let snapshot = wait(&engine, workspace);
    let evidence = &snapshot.evidence[0];
    std::fs::write(
        engine
            .store
            .directory(workspace)
            .join(&evidence.relative_path),
        "changed",
    )
    .unwrap();
    assert_eq!(
        engine
            .store
            .read_evidence(workspace, evidence.id)
            .unwrap_err()
            .code,
        "EvidenceIntegrityError"
    );
    let conn = engine.store.connect(workspace).unwrap();
    conn.execute(
        "UPDATE evidence SET relative_path='../outside' WHERE id=?1",
        [evidence.id.to_string()],
    )
    .unwrap();
    assert_eq!(
        engine
            .store
            .read_evidence(workspace, evidence.id)
            .unwrap_err()
            .code,
        "StorageError"
    );
}

#[test]
fn discovery_transaction_rolls_back_asset_provenance_and_events() {
    let (_temp, engine, workspace, target) = setup();
    engine
        .start(
            workspace,
            target,
            ChainKind::Synthetic,
            serde_json::Value::Null,
        )
        .unwrap();
    let before = wait(&engine, workspace);
    let discoveries = vec![
        Discovery {
            asset_type: AssetType::Subdomain,
            value: "new.example.test".into(),
            source: Some("example.test".into()),
            relationship: Some(RelationshipType::HasSubdomain),
            observation: None,
            metadata: json!({}),
        },
        Discovery {
            asset_type: AssetType::Subdomain,
            value: "broken.example.test".into(),
            source: Some("missing.test".into()),
            relationship: Some(RelationshipType::HasSubdomain),
            observation: None,
            metadata: json!({}),
        },
    ];
    assert!(engine
        .store
        .persist_discoveries(
            workspace,
            before.provider_runs[0].id,
            before.evidence[0].id,
            "SyntheticDiscoveryProvider",
            &discoveries
        )
        .is_err());
    let after = engine.store.snapshot(workspace).unwrap();
    assert_eq!(
        serde_json::to_value(before).unwrap(),
        serde_json::to_value(after).unwrap()
    );
}

#[test]
fn cancellation_is_durable_and_global_concurrency_is_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::open(
        Store::open(temp.path()).unwrap(),
        Duration::from_millis(100),
    )
    .unwrap();
    let workspace = engine
        .store
        .create_workspace("Cancel", &["example.test".into()])
        .unwrap();
    let target = engine
        .store
        .add_target(workspace.id, "example.test")
        .unwrap();
    let run = engine
        .start(
            workspace.id,
            target.id,
            ChainKind::Synthetic,
            serde_json::Value::Null,
        )
        .unwrap();
    assert_eq!(
        engine
            .start(
                workspace.id,
                target.id,
                ChainKind::Synthetic,
                serde_json::Value::Null
            )
            .unwrap_err()
            .code,
        "CoreBusy"
    );
    engine.cancel(workspace.id, run.id).unwrap();
    let snapshot = wait(&engine, workspace.id);
    assert_eq!(snapshot.chains[0].status, ChainStatus::Cancelled);
    assert!(snapshot
        .tasks
        .iter()
        .all(|t| t.status == TaskStatus::Cancelled));
    let count: i64 = engine
        .store
        .connect(workspace.id)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM audit_events WHERE action='ReconCancelled'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn workspace_isolation_and_exclusive_helper_ownership() {
    let (temp, engine, workspace, target) = setup();
    assert!(Engine::open(Store::open(temp.path()).unwrap(), Duration::ZERO).is_err());
    let other = engine
        .store
        .create_workspace("Other", &["example.test".into()])
        .unwrap();
    assert_eq!(
        engine
            .start(
                other.id,
                target,
                ChainKind::Synthetic,
                serde_json::Value::Null
            )
            .unwrap_err()
            .code,
        "InvalidTarget"
    );
    engine
        .start(
            workspace,
            target,
            ChainKind::Synthetic,
            serde_json::Value::Null,
        )
        .unwrap();
    let snapshot = wait(&engine, workspace);
    assert!(engine
        .store
        .read_evidence(other.id, snapshot.evidence[0].id)
        .is_err());
    let conn = engine.store.connect(other.id).unwrap();
    assert!(conn
        .execute(
            "INSERT INTO asset_relationships VALUES(?1,?2,?3,?3,'resolves_to','now')",
            rusqlite::params![
                Id::new_v4().to_string(),
                other.id.to_string(),
                snapshot.assets[0].id.to_string()
            ]
        )
        .is_err());
}

#[test]
fn interrupted_run_is_recovered_without_rescanning() {
    let (temp, engine, workspace, target) = setup();
    engine
        .start(
            workspace,
            target,
            ChainKind::Synthetic,
            serde_json::Value::Null,
        )
        .unwrap();
    let snapshot = wait(&engine, workspace);
    let conn = engine.store.connect(workspace).unwrap();
    conn.execute("UPDATE chain_runs SET status='RUNNING'", [])
        .unwrap();
    conn.execute(
        "UPDATE chain_stages SET status='RUNNING' WHERE position=0",
        [],
    )
    .unwrap();
    conn.execute("UPDATE tasks SET status='RUNNING'", [])
        .unwrap();
    drop(conn);
    drop(engine);
    let reopened = Engine::open(Store::open(temp.path()).unwrap(), Duration::ZERO).unwrap();
    let after = reopened.store.snapshot(workspace).unwrap();
    assert_eq!(after.chains[0].status, ChainStatus::Failed);
    assert_eq!(after.chains[0].error_code.as_deref(), Some("Interrupted"));
    assert_eq!(after.assets.len(), snapshot.assets.len());
    assert!(reopened.idle());
}
