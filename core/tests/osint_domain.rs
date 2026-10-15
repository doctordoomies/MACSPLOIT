//! Milestone 6 / Issue #66: Domain / public-infrastructure OSINT (theHarvester,
//! native RDAP, native certificate transparency), driven entirely offline by
//! `fixtures/fake-theharvester.sh` and a static web transport. No network; reserved
//! `.test` names only.

use macsploit_core::{
    assets::{AssetType, Id, RelationshipType},
    database::Store,
    dns::{DnsResolver, StaticDnsResolver},
    events::ChainStatus,
    orchestration::{ChainKind, Engine, Snapshot},
    process::ToolConfig,
    web::StaticWebTransport,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

const CT_URL: &str = "https://crt.sh/?q=%25.example.test&output=json";
const BOOTSTRAP_URL: &str = "https://data.iana.org/rdap/dns.json";
const RDAP_URL: &str = "https://rdap.registry.test/v1/domain/example.test";

const CT_BODY: &str = r#"[
  {"id":11,"issuer_name":"C=US, O=Example CA","common_name":"api.example.test","name_value":"api.example.test\n*.example.test","not_before":"2025-01-01T00:00:00","not_after":"2099-01-01T00:00:00"},
  {"id":12,"issuer_name":"C=US, O=Example CA","common_name":"old.example.test","name_value":"old.example.test","not_before":"2018-01-01T00:00:00","not_after":"2019-01-01T00:00:00"}
]"#;
const BOOTSTRAP: &str =
    r#"{"version":"1.0","services":[[["test"],["https://rdap.registry.test/v1/"]]]}"#;
const RDAP_BODY: &str = r#"{"objectClassName":"domain","ldhName":"example.test","handle":"EX-1",
  "status":["active"],"events":[{"eventAction":"registration","eventDate":"2001-02-03T04:05:06Z"}],
  "nameservers":[{"ldhName":"ns1.dns-host.test"}],
  "entities":[{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Synthetic Registrant"]]]}]}"#;

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
        .insert("theHarvester".into(), fixture("fake-theharvester.sh"));
    tools
        .overrides
        .insert("subfinder".into(), fixture("fake-subfinder.sh"));
    tools
        .overrides
        .insert("nmap".into(), fixture("fake-nmap.sh"));
    tools
        .overrides
        .insert("httpx".into(), fixture("fake-httpx.sh"));
    tools
}

fn web() -> StaticWebTransport {
    StaticWebTransport::new()
        .with_response(
            CT_URL,
            200,
            &[("Content-Type", "application/json")],
            CT_BODY,
        )
        .with_response(BOOTSTRAP_URL, 200, &[], BOOTSTRAP)
        .with_response(RDAP_URL, 200, &[], RDAP_BODY)
}

fn resolver() -> Arc<dyn DnsResolver> {
    let ip = |v: &str| v.parse::<Ipv4Addr>().unwrap();
    Arc::new(
        StaticDnsResolver::new()
            .with("api.example.test", &[ip("192.0.2.10")], &[])
            .with("dev.example.test", &[ip("192.0.2.11")], &[]),
    )
}

fn open(root: &Path, web: StaticWebTransport) -> Engine {
    Engine::open_with_web(
        Store::open(root).unwrap(),
        Duration::ZERO,
        tools(),
        resolver(),
        Arc::new(web),
    )
    .unwrap()
}

fn workspace(engine: &Engine, scope: &[&str]) -> Id {
    let scope: Vec<String> = scope.iter().map(|s| (*s).to_owned()).collect();
    engine
        .store
        .create_workspace("Domain OSINT", &scope)
        .unwrap()
        .id
}

fn wait(engine: &Engine, ws: Id) -> Snapshot {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !engine.idle() {
        assert!(Instant::now() < deadline, "chain timed out");
        thread::sleep(Duration::from_millis(5));
    }
    engine.store.snapshot(ws).unwrap()
}

fn run(engine: &Engine, ws: Id, target: Id, provider: &str) -> Snapshot {
    engine
        .start(
            ws,
            target,
            ChainKind::DomainOsint,
            json!({ "provider_id": provider }),
        )
        .unwrap();
    wait(engine, ws)
}

fn asset<'a>(
    snap: &'a Snapshot,
    kind: AssetType,
    identity: &str,
) -> &'a macsploit_core::assets::Asset {
    snap.assets
        .iter()
        .find(|a| a.asset_type == kind && a.canonical_identity == identity)
        .unwrap_or_else(|| panic!("missing {kind:?} {identity}"))
}

fn providers_observing(snap: &Snapshot, asset: Id) -> Vec<String> {
    let mut providers: Vec<String> = snap
        .observations
        .iter()
        .filter(|o| o.asset_id == asset)
        .filter_map(|o| {
            o.metadata
                .as_ref()?
                .get("provider")?
                .as_str()
                .map(str::to_owned)
        })
        .collect();
    providers.sort();
    providers
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

/// The #66 regression example: theHarvester reports api.example.test and
/// person@example.test; CT reports api.example.test and old.example.test. Result:
/// one canonical api asset with separate per-provider observations and evidence,
/// old marked passive/historical, the email with theHarvester provenance, nothing
/// probed, and everything intact after a restart. (OWASP Amass is not integrated;
/// see docs/osint.md for why.)
#[test]
fn regression_example_dedupes_hosts_keeps_provenance_and_never_probes() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("store");
    let ws = {
        let engine = open(&root, web());
        let ws = workspace(&engine, &["example.test", "*.example.test"]);
        let target = engine.store.add_target(ws, "example.test").unwrap();
        run(&engine, ws, target.id, "theharvester");
        let snap = run(&engine, ws, target.id, "native_ct");
        assert!(snap
            .chains
            .iter()
            .all(|c| c.status == ChainStatus::Completed));
        engine.shutdown();
        ws
    };
    let engine = open(&root, StaticWebTransport::new());
    let snap = engine.store.snapshot(ws).unwrap();

    // One canonical api asset, one observation per provider run.
    let api = asset(&snap, AssetType::Subdomain, "api.example.test");
    assert_eq!(
        providers_observing(&snap, api.id),
        ["native_ct", "theharvester"]
    );
    assert_eq!(api.metadata["in_scope"], true);
    let runs: BTreeSet<_> = snap
        .observations
        .iter()
        .filter(|o| o.asset_id == api.id)
        .map(|o| o.provider_run_id)
        .collect();
    assert_eq!(runs.len(), 2, "distinct provider runs");
    // Every observation is backed by persisted evidence from its own run.
    for o in snap.observations.iter().filter(|o| o.asset_id == api.id) {
        let evidence = snap
            .evidence
            .iter()
            .find(|e| Some(e.id) == o.evidence_id)
            .expect("observation evidence exists");
        assert_eq!(Some(evidence.provider_run_id), o.provider_run_id);
        engine.store.read_evidence(ws, evidence.id).unwrap();
        let meta = o.metadata.as_ref().unwrap();
        assert_eq!(meta["kind"], "osint_domain_observation");
        assert_eq!(meta["passive"], true);
        assert_eq!(meta["liveness"], "unverified");
        assert_eq!(o.confidence, "REPORTED");
    }

    // old.example.test: CT only, historical, expired certificates only.
    let old = asset(&snap, AssetType::Subdomain, "old.example.test");
    let old_obs: Vec<_> = snap
        .observations
        .iter()
        .filter(|o| o.asset_id == old.id)
        .collect();
    assert_eq!(old_obs.len(), 1);
    let meta = old_obs[0].metadata.as_ref().unwrap();
    assert_eq!(meta["provider"], "native_ct");
    assert_eq!(meta["historical"], true);
    assert_eq!(meta["facts"]["all_certificates_expired"], true);
    assert!(meta["note"].as_str().unwrap().contains("Historical"));

    // The email keeps theHarvester provenance and a has_email relationship.
    let domain = asset(&snap, AssetType::Domain, "example.test");
    let email = asset(&snap, AssetType::EmailAddress, "person@example.test");
    assert_eq!(providers_observing(&snap, email.id), ["theharvester"]);
    assert!(snap
        .relationships
        .iter()
        .any(|r| r.source_asset_id == domain.id
            && r.destination_asset_id == email.id
            && r.relationship_type == RelationshipType::HasEmail));
    // Out-of-domain values reported by the source are never kept.
    assert!(!snap
        .assets
        .iter()
        .any(|a| a.canonical_identity.contains("unrelated.test")));

    // Passive IP pair: observed_ip from the host, never resolves_to.
    let www = asset(&snap, AssetType::Subdomain, "www.example.test");
    let ip = asset(&snap, AssetType::IPAddress, "192.0.2.10");
    assert!(snap
        .relationships
        .iter()
        .any(|r| r.source_asset_id == www.id
            && r.destination_asset_id == ip.id
            && r.relationship_type == RelationshipType::ObservedIp));
    assert!(!snap
        .relationships
        .iter()
        .any(|r| r.relationship_type == RelationshipType::ResolvesTo));

    // No hidden follow-on work: exactly the two requested provider runs, no other
    // stages with capabilities, and no people names stored anywhere.
    let ids: Vec<_> = snap
        .provider_runs
        .iter()
        .map(|r| r.provider_id.as_str())
        .collect();
    assert_eq!(ids, ["theharvester", "native_ct"]);
    assert!(snap
        .stages
        .iter()
        .filter_map(|s| s.capability)
        .all(|c| c == macsploit_core::providers::Capability::DomainOsint));
    let everything = serde_json::to_string(&snap.observations).unwrap();
    assert!(!everything.contains("Synthetic Person"));

    // theHarvester was invoked with the passive allow-list only.
    let harvester_run = &snap.provider_runs[0];
    let env: Value = serde_json::from_str(
        &engine
            .store
            .read_evidence(ws, harvester_run.raw_output_reference.unwrap())
            .unwrap(),
    )
    .unwrap();
    let command: Vec<&str> = env["command"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    for forbidden in [
        "-r",
        "-n",
        "-c",
        "-t",
        "-s",
        "--screenshot",
        "-a",
        "-p",
        "-e",
    ] {
        assert!(!command.contains(&forbidden), "{forbidden}");
    }
    assert!(
        env["artifacts"][0]["evidence_id"].is_string(),
        "report kept"
    );
}

#[test]
fn rdap_records_minimized_registration_and_nameservers() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(temp.path(), web());
    let ws = workspace(&engine, &["example.test"]);
    let target = engine.store.add_target(ws, "example.test").unwrap();
    let snap = run(&engine, ws, target.id, "native_rdap");
    assert_eq!(snap.chains[0].status, ChainStatus::Completed);
    let domain = asset(&snap, AssetType::Domain, "example.test");
    let summary = snap
        .observations
        .iter()
        .filter(|o| o.asset_id == domain.id)
        .find_map(|o| {
            o.metadata
                .clone()
                .filter(|m| m["kind"] == "osint_run_summary")
        })
        .unwrap();
    assert_eq!(summary["kind"], "osint_run_summary");
    assert_eq!(summary["subject_kind"], "DOMAIN");
    assert_eq!(summary["registration"]["found"], true);
    assert_eq!(summary["registration"]["entity_roles"]["registrant"], 1);
    assert!(!summary.to_string().contains("Synthetic Registrant"));
    let ns = asset(&snap, AssetType::Hostname, "ns1.dns-host.test");
    assert_eq!(
        ns.metadata["in_scope"], false,
        "nameserver outside scope is flagged"
    );
    assert!(snap
        .relationships
        .iter()
        .any(|r| r.source_asset_id == domain.id
            && r.destination_asset_id == ns.id
            && r.relationship_type == RelationshipType::HasNameserver));
    // Registry response, bootstrap, and the request-log envelope are all evidence.
    assert_eq!(snap.evidence.len(), 3);
    let env = envelope(&engine, ws, &snap);
    let names: Vec<_> = env["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["rdap_response", "rdap_bootstrap"]);
    assert_eq!(env["network_activity"], "NETWORK");
}

#[test]
fn domain_osint_requires_an_in_scope_domain_and_a_domain_osint_provider() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(temp.path(), web());
    let ws = workspace(&engine, &["other.test"]);
    let outside = engine.store.add_target(ws, "example.test").unwrap();
    let err = engine
        .start(ws, outside.id, ChainKind::DomainOsint, Value::Null)
        .map(|_| ())
        .unwrap_err();
    assert_eq!(err.code, "ScopeViolation");

    let inside = engine.store.add_target(ws, "other.test").unwrap();
    for provider in ["sherlock", "subfinder", "phoneinfoga", "native_http"] {
        let err = engine
            .start(
                ws,
                inside.id,
                ChainKind::DomainOsint,
                json!({ "provider_id": provider }),
            )
            .map(|_| ())
            .unwrap_err();
        assert_eq!(err.code, "ProviderUnsupported", "{provider}");
    }
    let user = engine.store.add_target(ws, "@octo-synthetic").unwrap();
    let err = engine
        .start(ws, user.id, ChainKind::DomainOsint, Value::Null)
        .map(|_| ())
        .unwrap_err();
    assert_eq!(err.code, "InvalidTarget");
    // Domain providers are not offered for identifier OSINT either.
    let err = engine
        .start(
            ws,
            user.id,
            ChainKind::UsernameOsint,
            json!({"provider_id": "native_ct"}),
        )
        .map(|_| ())
        .unwrap_err();
    assert_eq!(err.code, "ProviderUnsupported");
    assert!(engine.store.snapshot(ws).unwrap().chains.is_empty());
}

#[test]
fn failures_timeouts_and_malformed_output_keep_evidence() {
    let cases: Vec<(&str, &str, StaticWebTransport, &str)> = vec![
        (
            "example.test",
            "native_ct",
            StaticWebTransport::new().with_response(CT_URL, 502, &[], "bad gateway"),
            "ProviderFailure",
        ),
        (
            "example.test",
            "native_ct",
            StaticWebTransport::new().with_timeout(CT_URL),
            "ProviderTimeout",
        ),
        (
            "example.test",
            "native_ct",
            StaticWebTransport::new().with_response(CT_URL, 200, &[], "{not json"),
            "ProviderFailure",
        ),
        (
            "example.test",
            "native_rdap",
            StaticWebTransport::new().with_failure(BOOTSTRAP_URL, "tls handshake failed"),
            "ProviderFailure",
        ),
        (
            "failing.test",
            "theharvester",
            StaticWebTransport::new(),
            "ProviderFailure",
        ),
        (
            "malformed.test",
            "theharvester",
            StaticWebTransport::new(),
            "ProviderFailure",
        ),
    ];
    for (domain, provider, transport, code) in cases {
        let temp = tempfile::tempdir().unwrap();
        let engine = open(temp.path(), transport);
        let ws = workspace(&engine, &[domain]);
        let target = engine.store.add_target(ws, domain).unwrap();
        let snap = run(&engine, ws, target.id, provider);
        assert_eq!(
            snap.chains[0].status,
            ChainStatus::Failed,
            "{provider} {domain}"
        );
        assert_eq!(
            snap.chains[0].error_code.as_deref(),
            Some(code),
            "{provider} {domain}"
        );
        assert!(
            !snap.evidence.is_empty(),
            "evidence kept for {provider} {domain}"
        );
        for evidence in &snap.evidence {
            engine.store.read_evidence(ws, evidence.id).unwrap();
        }
        // Nothing beyond the subject target was created.
        assert!(snap
            .assets
            .iter()
            .all(|a| a.asset_type == AssetType::Domain));
    }
}

#[test]
fn zero_results_and_oversized_ct_responses() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(
        temp.path(),
        StaticWebTransport::new().with_response(CT_URL, 200, &[], "[]"),
    );
    let ws = workspace(&engine, &["example.test", "empty.test"]);
    let target = engine.store.add_target(ws, "example.test").unwrap();
    let snap = run(&engine, ws, target.id, "native_ct");
    assert_eq!(snap.chains[0].status, ChainStatus::Completed);
    assert_eq!(snap.assets.len(), 1);
    let empty = engine.store.add_target(ws, "empty.test").unwrap();
    let snap = run(&engine, ws, empty.id, "theharvester");
    assert_eq!(snap.chains[1].status, ChainStatus::Completed);

    let big = format!(
        "[{}]",
        "{\"name_value\":\"x.example.test\"},".repeat(140_000)
    );
    let temp = tempfile::tempdir().unwrap();
    let engine = open(
        temp.path(),
        StaticWebTransport::new().with_response(CT_URL, 200, &[], &big),
    );
    let ws = workspace(&engine, &["example.test"]);
    let target = engine.store.add_target(ws, "example.test").unwrap();
    let snap = run(&engine, ws, target.id, "native_ct");
    assert_eq!(
        snap.chains[0].error_code.as_deref(),
        Some("BudgetExceeded"),
        "{:?}",
        snap.chains[0].error_message
    );
    // 4 MiB of captured bytes, stored as four 1 MiB evidence chunks + envelope.
    assert_eq!(snap.evidence.len(), 5);
}

#[test]
fn cancellation_keeps_captured_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(temp.path(), StaticWebTransport::new());
    let ws = workspace(&engine, &["slow.test"]);
    let target = engine.store.add_target(ws, "slow.test").unwrap();
    let chain = engine
        .start(
            ws,
            target.id,
            ChainKind::DomainOsint,
            json!({"provider_id": "theharvester"}),
        )
        .unwrap();
    thread::sleep(Duration::from_millis(150));
    engine.cancel(ws, chain.id).unwrap();
    let snap = wait(&engine, ws);
    assert_eq!(snap.chains[0].status, ChainStatus::Cancelled);
    let env = envelope(&engine, ws, &snap);
    assert_eq!(env["cancelled"], true);
    assert!(env["stdout"]
        .as_str()
        .unwrap()
        .contains("theHarvester 4.11.1"));
}

/// Existing Subfinder data is reused, not re-collected: Domain OSINT never runs
/// Subfinder, and a CT name Subfinder already found is one canonical Subdomain
/// carrying both providers' observations. Repeated runs stay distinguishable and
/// never overwrite the asset's first-seen metadata.
#[test]
fn subfinder_data_is_reused_and_repeated_runs_stay_distinguishable() {
    let temp = tempfile::tempdir().unwrap();
    let engine = open(temp.path(), web());
    let ws = workspace(&engine, &["example.test", "*.example.test", "192.0.2.0/24"]);
    let target = engine.store.add_target(ws, "example.test").unwrap();
    engine
        .start(ws, target.id, ChainKind::DomainRecon, Value::Null)
        .unwrap();
    let before = wait(&engine, ws);
    let api_before = asset(&before, AssetType::Subdomain, "api.example.test").clone();
    let subfinder_runs = before
        .provider_runs
        .iter()
        .filter(|r| r.provider_id == "subfinder")
        .count();

    run(&engine, ws, target.id, "native_ct");
    let snap = run(&engine, ws, target.id, "native_ct");
    assert_eq!(
        snap.provider_runs
            .iter()
            .filter(|r| r.provider_id == "subfinder")
            .count(),
        subfinder_runs,
        "Domain OSINT never re-runs Subfinder"
    );
    let api = asset(&snap, AssetType::Subdomain, "api.example.test");
    assert_eq!(api.id, api_before.id);
    assert_eq!(api.first_seen, api_before.first_seen);
    assert_eq!(
        api.metadata, api_before.metadata,
        "prior metadata not overwritten"
    );
    let providers = providers_observing(&snap, api.id);
    assert_eq!(
        providers.iter().filter(|p| *p == "native_ct").count(),
        2,
        "one observation per CT run"
    );
    assert!(snap
        .observations
        .iter()
        .any(|o| o.asset_id == api.id && o.discovered_by.to_lowercase().contains("subfinder")));
}

/// Issue #71: an out-of-scope Domain OSINT target is refused by the core until the
/// analyst authorizes the exact entry; the entry persists across a restart and the
/// run then proceeds. Identifier subjects never need host scope.
#[test]
fn domain_osint_authorization_is_exact_persistent_and_core_enforced() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("store");
    let (ws, target) = {
        let engine = open(&root, web());
        let ws = workspace(&engine, &["other.test"]);
        let target = engine.store.add_target(ws, "example.test").unwrap();
        let status = engine.store.target_scope_status(ws, target.id).unwrap();
        assert!(!status.authorized);
        assert_eq!(status.required_scope_entry.as_deref(), Some("example.test"));
        let err = engine
            .start(ws, target.id, ChainKind::DomainOsint, Value::Null)
            .map(|_| ())
            .unwrap_err();
        assert_eq!(err.code, "ScopeViolation");
        let result = engine.store.authorize_target(ws, target.id).unwrap();
        assert!(result.authorized);
        assert_eq!(result.added_entry.as_deref(), Some("example.test"));
        // Exactly the core-reported entry: no wildcard or sibling widening.
        let mut scope = result.workspace.scope.clone();
        scope.sort();
        assert_eq!(scope, ["example.test", "other.test"]);
        engine.shutdown();
        (ws, target.id)
    };
    let engine = open(&root, web());
    assert!(
        engine
            .store
            .target_scope_status(ws, target)
            .unwrap()
            .authorized
    );
    let snap = run(&engine, ws, target, "native_ct");
    assert_eq!(snap.chains[0].status, ChainStatus::Completed);
    assert!(!snap
        .workspace
        .scope
        .iter()
        .any(|entry| entry.starts_with("*.")));
    // Identifier OSINT is not forced through host scope.
    let user = engine.store.add_target(ws, "@octo-synthetic").unwrap();
    assert!(engine
        .start(
            ws,
            user.id,
            ChainKind::UsernameOsint,
            json!({"provider_id": "native_ct"})
        )
        .map(|_| ())
        .is_err_and(|e| e.code == "ProviderUnsupported"));
}
