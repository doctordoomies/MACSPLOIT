//! Milestone 1.3 coverage for the core-authoritative scope-status and Recon
//! authorization flow (target_scope_status / authorize_target). No network activity.

use macsploit_core::database::Store;

fn store() -> (tempfile::TempDir, Store) {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    (temp, store)
}

#[test]
fn scope_status_reports_coverage_with_core_logic() {
    let (_t, store) = store();
    let ws = store
        .create_workspace(
            "status",
            &[
                "example.test".into(),
                "*.example.test".into(),
                "192.0.2.0/24".into(),
                "2001:db8::/32".into(),
            ],
        )
        .unwrap();
    let add = |v: &str| store.add_target(ws.id, v).unwrap();

    // exact domain covered; wildcard-covered hostname; exact/CIDR IPv4; IPv6 CIDR; URL host.
    let exact = add("example.test");
    let wildcarded = add("api.example.test");
    let ipv4 = add("192.0.2.25");
    let ipv6 = add("2001:db8::10");
    let url = add("https://app.example.test:8443/admin");
    let outside = add("other.test");

    // Failure messages name the case, never the target value (targets may be
    // analyst identifiers, which must not be echoed into logs).
    for (case, t, expected) in [
        ("exact domain", &exact, true),
        ("wildcard hostname", &wildcarded, true),
        ("IPv4 in CIDR", &ipv4, true),
        ("IPv6 in CIDR", &ipv6, true),
        ("URL host", &url, true),
        ("outside", &outside, false),
    ] {
        assert_eq!(
            store.target_scope_status(ws.id, t.id).unwrap().authorized,
            expected,
            "{case}"
        );
    }
    // The required entry for the URL is the exact host, not a sibling or wildcard.
    let status = store.target_scope_status(ws.id, url.id).unwrap();
    assert_eq!(
        status.required_scope_entry.as_deref(),
        Some("app.example.test")
    );
}

#[test]
fn authorize_target_adds_only_the_narrowest_exact_entry() {
    for (input, expected_entry) in [
        ("google.example", "google.example"),     // domain
        ("api.example.test", "api.example.test"), // hostname-style domain
        ("192.0.2.25", "192.0.2.25"),             // IPv4
        ("2001:db8::10", "2001:db8::10"),         // IPv6
        ("https://app.example.test:8443/admin", "app.example.test"), // URL host only
    ] {
        let (_t, store) = store();
        let ws = store.create_workspace("authz", &[]).unwrap();
        let target = store.add_target(ws.id, input).unwrap();

        // Not covered before.
        assert!(
            !store
                .target_scope_status(ws.id, target.id)
                .unwrap()
                .authorized
        );

        let result = store.authorize_target(ws.id, target.id).unwrap();
        assert!(result.authorized);
        assert_eq!(
            result.added_entry.as_deref(),
            Some(expected_entry),
            "input {input}"
        );

        // Exactly one entry, no wildcard, no CIDR.
        let scope = store.workspace(ws.id).unwrap().scope;
        assert_eq!(scope, vec![expected_entry.to_string()], "input {input}");
        assert!(!scope.iter().any(|e| e.starts_with("*.") || e.contains('/')));

        // Now covered (re-checked by core logic) and persisted.
        assert!(
            store
                .target_scope_status(ws.id, target.id)
                .unwrap()
                .authorized
        );
    }
}

#[test]
fn authorize_target_is_a_noop_when_already_covered() {
    let (_t, store) = store();
    let ws = store
        .create_workspace("covered", &["example.test".into()])
        .unwrap();
    let target = store.add_target(ws.id, "example.test").unwrap();
    let before = store.snapshot(ws.id).unwrap();

    let result = store.authorize_target(ws.id, target.id).unwrap();
    assert!(result.authorized);
    assert!(result.added_entry.is_none());

    let after = store.snapshot(ws.id).unwrap();
    // No duplicate scope entry and no new event from a no-op authorization.
    assert_eq!(after.workspace.scope, vec!["example.test".to_string()]);
    assert_eq!(after.last_sequence, before.last_sequence);
}

#[test]
fn authorize_target_persists_and_emits_a_scope_event_without_starting_work() {
    let (_t, store) = store();
    let ws = store.create_workspace("event", &[]).unwrap();
    let target = store.add_target(ws.id, "192.0.2.25").unwrap();

    store.authorize_target(ws.id, target.id).unwrap();
    let snap = store.snapshot(ws.id).unwrap();

    // Durable scope-update event tagged as coming from the Recon authorization flow.
    let scope_event = snap
        .events
        .iter()
        .rev()
        .find(|e| format!("{:?}", e.event_type) == "WorkspaceScopeUpdated")
        .expect("scope update event");
    assert_eq!(
        scope_event.payload["added"],
        serde_json::json!("192.0.2.25")
    );
    assert_eq!(
        scope_event.payload["source"],
        serde_json::json!("recon_authorization")
    );
    // Authorization itself starts no chain, runs no provider, creates no evidence.
    assert!(snap.chains.is_empty());
    assert!(snap.provider_runs.is_empty());
    assert!(snap.evidence.is_empty());

    // Reopen: the added entry is durable.
    drop(store);
    let reopened = Store::open(_t.path()).unwrap();
    assert_eq!(
        reopened.workspace(ws.id).unwrap().scope,
        vec!["192.0.2.25".to_string()]
    );
}

#[test]
fn authorize_target_rejects_unauthorizable_target_types() {
    let (_t, store) = store();
    let ws = store.create_workspace("cidr", &[]).unwrap();
    let cidr = store.add_target(ws.id, "192.0.2.0/24").unwrap();
    let err = store.authorize_target(ws.id, cidr.id).unwrap_err();
    assert_eq!(err.code, "InvalidTarget");
    // Scope unchanged.
    assert!(store.workspace(ws.id).unwrap().scope.is_empty());
}
