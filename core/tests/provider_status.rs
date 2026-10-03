//! Provider Center status probes use only local fake executables, never scanners.
use macsploit_core::{
    database::Store,
    dns::StaticDnsResolver,
    orchestration::Engine,
    process::{Installation, ToolConfig},
    protocol::{self, Command, Request},
    providers::{ProviderRegistry, ProviderStatus},
};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, sync::Arc, time::Duration};

fn tools(root: &Path, body: &str) -> ToolConfig {
    let executable = root.join("fake-tool");
    fs::write(&executable, body).unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let mut tools = ToolConfig::default();
    for name in ["subfinder", "nmap", "httpx", "katana"] {
        tools.overrides.insert(name.into(), executable.clone());
    }
    tools
}

#[test]
fn registry_and_protocol_report_paths_setup_and_native_providers_without_workspace() {
    let temp = tempfile::tempdir().unwrap();
    let tools = tools(temp.path(), "#!/bin/sh\nprintf 'fake version 2.6.6\\n'\n");
    let engine = Engine::open_with(
        Store::open(temp.path().join("store")).unwrap(),
        Duration::ZERO,
        tools,
        Arc::new(StaticDnsResolver::new()),
    )
    .unwrap();
    let response = protocol::handle(
        &engine,
        Request {
            protocol_version: 1,
            request_id: "provider-center-test".into(),
            command: Command::ListProviders {},
        },
    );
    assert!(response.error.is_none());
    assert_eq!(response.protocol_version, 1);
    let statuses: Vec<ProviderStatus> = serde_json::from_value(response.result.unwrap()).unwrap();
    assert_eq!(statuses.len(), 7);
    let mut built_in = 0;
    for status in statuses {
        match status.installation {
            Installation::BuiltIn => {
                built_in += 1;
                assert!(status.setup.is_none());
            }
            Installation::Installed { version, path } => {
                assert_eq!(version, "2.6.6");
                assert_eq!(path.unwrap(), temp.path().join("fake-tool"));
                let setup = status.setup.unwrap();
                assert_eq!(
                    setup.install_command.unwrap(),
                    format!("brew install {}", status.metadata.id)
                );
                assert!(setup.documentation.unwrap().starts_with("https://"));
                assert!(setup.homepage.unwrap().starts_with("https://"));
            }
            state => panic!("unexpected status {state:?}"),
        }
    }
    assert_eq!(built_in, 3);
}

#[test]
fn probes_distinguish_unknown_version_missing_and_execution_errors() {
    let temp = tempfile::tempdir().unwrap();
    let registry = ProviderRegistry::default();
    for (body, expected) in [
        ("#!/bin/sh\necho no-version\n", "INSTALLED"),
        ("#!/bin/sh\nexit 3\n", "EXECUTION_ERROR"),
        ("invalid executable format", "EXECUTION_ERROR"),
    ] {
        let config = tools(temp.path(), body);
        for status in registry
            .status(&config)
            .into_iter()
            .filter(|s| s.setup.is_some())
        {
            let value = serde_json::to_value(status).unwrap();
            assert_eq!(value["installation"]["state"], expected);
            if expected == "INSTALLED" {
                assert_eq!(value["installation"]["version"], "unknown");
            }
        }
    }
    let mut config = ToolConfig::default();
    for name in ["subfinder", "nmap", "httpx", "katana"] {
        config
            .overrides
            .insert(name.into(), temp.path().join("missing"));
    }
    for status in registry
        .status(&config)
        .into_iter()
        .filter(|s| s.setup.is_some())
    {
        assert_eq!(status.installation, Installation::Missing);
    }
}

#[test]
fn version_one_statuses_remain_decodable_and_all_states_round_trip() {
    let legacy = r#"{"state":"INSTALLED","version":"1.2.3"}"#;
    assert_eq!(
        serde_json::from_str::<Installation>(legacy).unwrap(),
        Installation::Installed {
            version: "1.2.3".into(),
            path: None
        }
    );
    for state in [
        Installation::BuiltIn,
        Installation::Missing,
        Installation::UnsupportedVersion {
            version: "0.1".into(),
        },
        Installation::ExecutionError {
            message: "probe failed".into(),
        },
    ] {
        assert_eq!(
            serde_json::from_value::<Installation>(serde_json::to_value(&state).unwrap()).unwrap(),
            state
        );
    }
    // Old v1 ProviderStatus payloads omit setup and executable path.
    let value = serde_json::json!({"id":"future", "name":"Future", "description":"Offline fixture",
        "version":"1", "capabilities":[], "supported_target_types":[], "risk_class":"PASSIVE",
        "offline":true, "installation":{"state":"INSTALLED","version":"unknown"}});
    assert!(serde_json::from_value::<ProviderStatus>(value)
        .unwrap()
        .setup
        .is_none());
}
