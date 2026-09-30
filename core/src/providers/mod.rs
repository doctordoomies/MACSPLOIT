use crate::{
    assets::{Asset, AssetType, Discovery, RelationshipType},
    dns::{DnsOutcome, DnsResolver},
    error::{CoreError, Result},
    process::{self, Installation, ToolConfig},
    targets::TargetType,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    sync::{atomic::AtomicBool, Arc},
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskClass {
    Passive,
    ActiveLowImpact,
    Active,
    Validation,
    LabOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Capability {
    SubdomainDiscovery,
    DnsResolution,
    ServiceFingerprinting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderMetadata {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub capabilities: Vec<Capability>,
    pub supported_target_types: Vec<TargetType>,
    pub risk_class: RiskClass,
    /// True when the provider runs entirely offline (no external process).
    pub offline: bool,
}

/// Provider metadata paired with its live installation state, for the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderStatus {
    #[serde(flatten)]
    pub metadata: ProviderMetadata,
    pub installation: Installation,
}

/// Everything a provider learns from one execution. The orchestrator turns this
/// into a persisted evidence envelope; the provider's own parser reads `stdout`.
#[derive(Debug, Clone)]
pub struct Execution {
    pub target: String,
    pub capability: Capability,
    pub command: Vec<String>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_status: Option<i32>,
    pub pid: Option<u32>,
    pub timed_out: bool,
    pub started_at: String,
    pub ended_at: String,
}

impl Execution {
    /// Did the tool complete successfully (clean exit, no timeout)?
    pub fn succeeded(&self) -> bool {
        !self.timed_out && self.exit_status == Some(0)
    }
}

/// Execution environment passed to a provider: cancellation, wall-clock
/// deadline, and executable discovery configuration.
pub struct ProviderContext<'a> {
    pub cancelled: &'a AtomicBool,
    pub deadline: Instant,
    pub tools: &'a ToolConfig,
}

pub trait Provider: Send + Sync {
    fn metadata(&self) -> ProviderMetadata;
    /// Report whether the provider's backing tool is available. Offline
    /// providers are always installed.
    fn installation(&self, tools: &ToolConfig) -> Installation;
    fn execute(
        &self,
        target: &str,
        capability: Capability,
        inputs: &[Asset],
        ctx: &ProviderContext,
    ) -> Result<Execution>;
    fn parse(&self, execution: &Execution) -> Result<Vec<Discovery>>;
}

#[derive(Clone)]
pub struct ProviderRegistry {
    providers: Vec<Arc<dyn Provider>>,
}

impl ProviderRegistry {
    /// Build the registry with an explicit DNS resolver (injected in tests).
    pub fn new(resolver: Arc<dyn DnsResolver>) -> Self {
        Self {
            providers: vec![
                Arc::new(SyntheticDiscoveryProvider),
                Arc::new(SubfinderProvider),
                Arc::new(NativeDnsProvider::new(resolver)),
            ],
        }
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new(Arc::new(crate::dns::SystemDnsResolver::default()))
    }
}

impl ProviderRegistry {
    /// Select a provider purely by capability and target type (used when a chain
    /// stage does not pin a specific provider).
    pub fn select(
        &self,
        capability: Capability,
        target_type: TargetType,
    ) -> Result<Arc<dyn Provider>> {
        self.providers
            .iter()
            .find(|provider| {
                let metadata = provider.metadata();
                metadata.capabilities.contains(&capability)
                    && metadata.supported_target_types.contains(&target_type)
            })
            .cloned()
            .ok_or_else(|| {
                CoreError::new("ProviderFailure", "No compatible provider is registered.")
            })
    }

    /// Fetch a provider by its stable identifier and verify it still supports the
    /// requested capability and target type.
    pub fn named(
        &self,
        id: &str,
        capability: Capability,
        target_type: TargetType,
    ) -> Result<Arc<dyn Provider>> {
        let provider = self
            .providers
            .iter()
            .find(|provider| provider.metadata().id == id)
            .cloned()
            .ok_or_else(|| {
                CoreError::new("ProviderFailure", "The requested provider is not registered.")
            })?;
        let metadata = provider.metadata();
        if !metadata.capabilities.contains(&capability)
            || !metadata.supported_target_types.contains(&target_type)
        {
            return Err(CoreError::new(
                "ProviderFailure",
                "The pinned provider does not support this stage.",
            ));
        }
        Ok(provider)
    }

    pub fn metadata(&self) -> Vec<ProviderMetadata> {
        self.providers.iter().map(|p| p.metadata()).collect()
    }

    pub fn status(&self, tools: &ToolConfig) -> Vec<ProviderStatus> {
        self.providers
            .iter()
            .map(|provider| ProviderStatus {
                metadata: provider.metadata(),
                installation: provider.installation(tools),
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Synthetic provider (offline; Phase 0). Retained for tests, demos, and
// regression coverage. Produces invented discoveries with no external process.
// ---------------------------------------------------------------------------

pub struct SyntheticDiscoveryProvider;

#[derive(Serialize, Deserialize)]
struct SyntheticOutput {
    provider: String,
    input: String,
    capability: Capability,
    synthetic: bool,
    discoveries: Vec<Discovery>,
}

impl Provider for SyntheticDiscoveryProvider {
    fn metadata(&self) -> ProviderMetadata {
        ProviderMetadata {
            id: "synthetic".into(),
            name: "SyntheticDiscoveryProvider".into(),
            description: "Invented offline discoveries. No network, DNS, or external tools.".into(),
            version: "1.0.0".into(),
            risk_class: RiskClass::Passive,
            offline: true,
            capabilities: vec![
                Capability::SubdomainDiscovery,
                Capability::DnsResolution,
                Capability::ServiceFingerprinting,
            ],
            supported_target_types: vec![TargetType::Domain],
        }
    }

    fn installation(&self, _tools: &ToolConfig) -> Installation {
        Installation::Installed {
            version: "1.0.0".into(),
        }
    }

    fn execute(
        &self,
        target: &str,
        capability: Capability,
        inputs: &[Asset],
        _ctx: &ProviderContext,
    ) -> Result<Execution> {
        if target != "example.test" {
            return Err(CoreError::new(
                "ProviderFailure",
                "Phase 0 synthetic recon supports example.test only.",
            ));
        }
        let started_at = crate::now();
        let mut discoveries = Vec::new();
        let mut add = |asset_type, value: String, source: String, relationship, metadata| {
            discoveries.push(Discovery {
                asset_type,
                value,
                source: Some(source),
                relationship: Some(relationship),
                metadata,
            });
        };
        match capability {
            Capability::SubdomainDiscovery => {
                for value in [
                    "api.example.test",
                    "api.example.test",
                    "API.EXAMPLE.TEST",
                    "dev.example.test",
                ] {
                    add(
                        AssetType::Subdomain,
                        value.into(),
                        target.into(),
                        RelationshipType::HasSubdomain,
                        json!({"synthetic":true}),
                    );
                }
            }
            Capability::DnsResolution => {
                for input in inputs
                    .iter()
                    .filter(|a| a.asset_type == AssetType::Subdomain)
                {
                    let address = match input.canonical_identity.as_str() {
                        "api.example.test" => "192.0.2.10",
                        "dev.example.test" => "192.0.2.11",
                        _ => continue,
                    };
                    add(
                        AssetType::IPAddress,
                        address.into(),
                        input.canonical_identity.clone(),
                        RelationshipType::ResolvesTo,
                        json!({"synthetic":true}),
                    );
                }
            }
            Capability::ServiceFingerprinting => {
                for input in inputs
                    .iter()
                    .filter(|a| a.asset_type == AssetType::IPAddress)
                {
                    let ip = input.canonical_identity.as_str();
                    let services = match ip {
                        "192.0.2.10" => vec![(443, "HTTPS")],
                        "192.0.2.11" => vec![(22, "SSH"), (443, "HTTPS")],
                        _ => continue,
                    };
                    for (port, name) in services {
                        let port_id = format!("{ip}/tcp/{port}");
                        add(
                            AssetType::Port,
                            port_id.clone(),
                            ip.into(),
                            RelationshipType::Exposes,
                            json!({"synthetic":true,"host":ip,"port":port,"transport":"tcp"}),
                        );
                        add(
                            AssetType::Service,
                            format!("{port_id}/{}", name.to_lowercase()),
                            port_id,
                            RelationshipType::Serves,
                            json!({"synthetic":true,"host":ip,"name":name}),
                        );
                    }
                }
            }
        }
        let stdout = serde_json::to_vec_pretty(&SyntheticOutput {
            provider: "synthetic".into(),
            input: target.into(),
            capability,
            synthetic: true,
            discoveries,
        })?;
        Ok(Execution {
            target: target.into(),
            capability,
            command: vec!["synthetic".into()],
            stdout,
            stderr: Vec::new(),
            exit_status: Some(0),
            pid: None,
            timed_out: false,
            started_at,
            ended_at: crate::now(),
        })
    }

    fn parse(&self, execution: &Execution) -> Result<Vec<Discovery>> {
        if execution.stdout.len() > 1024 * 1024 {
            return Err(CoreError::new(
                "ProviderFailure",
                "Provider output exceeds the size budget.",
            ));
        }
        let output: SyntheticOutput = serde_json::from_slice(&execution.stdout).map_err(|_| {
            CoreError::new("ProviderFailure", "Synthetic provider output is malformed.")
        })?;
        if output.provider != "synthetic"
            || !output.synthetic
            || output.input != "example.test"
            || output.discoveries.len() > 100
        {
            return Err(CoreError::new(
                "ProviderFailure",
                "Synthetic provider output violates its contract.",
            ));
        }
        Ok(output.discoveries)
    }
}

// ---------------------------------------------------------------------------
// Subfinder provider (Phase 1A; first real external tool). Passive subdomain
// enumeration. Executes through the centralized process supervisor with an
// explicit argument array — never a shell.
// ---------------------------------------------------------------------------

pub struct SubfinderProvider;

/// Maximum captured bytes. Kept comfortably under the 1 MiB evidence limit once
/// wrapped in the JSON envelope alongside stderr and metadata.
const SUBFINDER_STDOUT_CAP: usize = 512 * 1024;
const SUBFINDER_STDERR_CAP: usize = 64 * 1024;
/// Bounds applied to untrusted output during parsing.
const MAX_RESULT_LINES: usize = 5000;
const MAX_LINE_BYTES: usize = 2048;

/// One JSONL record emitted by `subfinder -oJ`. Only `host` is required; other
/// fields are optional and retained as provenance metadata when present.
#[derive(Deserialize)]
struct SubfinderRecord {
    host: String,
    #[serde(default)]
    source: Option<String>,
}

impl SubfinderProvider {
    fn arguments(target: &str) -> Vec<String> {
        // -silent: only results on stdout. -oJ: JSON lines. The target has
        // already been validated/normalized by `targets::classify`, so it cannot
        // contain shell metacharacters or a leading dash.
        vec![
            "-d".into(),
            target.into(),
            "-silent".into(),
            "-oJ".into(),
        ]
    }
}

impl Provider for SubfinderProvider {
    fn metadata(&self) -> ProviderMetadata {
        ProviderMetadata {
            id: "subfinder".into(),
            name: "Subfinder".into(),
            description:
                "Passive subdomain enumeration via the external ProjectDiscovery subfinder tool."
                    .into(),
            version: "external".into(),
            risk_class: RiskClass::Passive,
            offline: false,
            capabilities: vec![Capability::SubdomainDiscovery],
            supported_target_types: vec![TargetType::Domain],
        }
    }

    fn installation(&self, tools: &ToolConfig) -> Installation {
        let Some(executable) = tools.locate("subfinder") else {
            return Installation::Missing;
        };
        let cancelled = AtomicBool::new(false);
        match process::run(
            &executable,
            &["-version".into()],
            &cancelled,
            Instant::now() + Duration::from_secs(5),
            SUBFINDER_STDERR_CAP,
            SUBFINDER_STDERR_CAP,
        ) {
            Ok(outcome) => {
                let mut text = String::from_utf8_lossy(&outcome.stdout).into_owned();
                text.push('\n');
                text.push_str(&String::from_utf8_lossy(&outcome.stderr));
                // Surface an unknown version explicitly rather than claiming one.
                let version = process::scan_version(&text).unwrap_or_else(|| "unknown".into());
                Installation::Installed { version }
            }
            Err(error) => Installation::ExecutionError {
                message: error.message,
            },
        }
    }

    fn execute(
        &self,
        target: &str,
        capability: Capability,
        _inputs: &[Asset],
        ctx: &ProviderContext,
    ) -> Result<Execution> {
        let executable = ctx.tools.locate("subfinder").ok_or_else(|| {
            CoreError::new(
                "ProviderMissing",
                "Subfinder is not installed. Install it manually to run domain recon.",
            )
        })?;
        let arguments = Self::arguments(target);
        let outcome = process::run(
            &executable,
            &arguments,
            ctx.cancelled,
            ctx.deadline,
            SUBFINDER_STDOUT_CAP,
            SUBFINDER_STDERR_CAP,
        )?;
        if outcome.cancelled {
            return Err(CoreError::new("Cancelled", "Domain recon cancelled."));
        }
        let mut command = vec![executable.to_string_lossy().into_owned()];
        command.extend(arguments);
        Ok(Execution {
            target: target.into(),
            capability,
            command,
            stdout: outcome.stdout,
            stderr: outcome.stderr,
            exit_status: outcome.exit_status,
            pid: outcome.pid,
            timed_out: outcome.timed_out,
            started_at: outcome.started_at,
            ended_at: outcome.ended_at,
        })
    }

    fn parse(&self, execution: &Execution) -> Result<Vec<Discovery>> {
        // Subfinder output is untrusted. Bound size, validate each host, and let
        // a malformed line be skipped without discarding valid discoveries.
        let text = String::from_utf8_lossy(&execution.stdout);
        let target = execution.target.as_str();
        let suffix = format!(".{target}");
        let mut discoveries = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (index, line) in text.lines().enumerate() {
            if index >= MAX_RESULT_LINES {
                break;
            }
            let line = line.trim();
            if line.is_empty() || line.len() > MAX_LINE_BYTES {
                continue;
            }
            // Prefer structured JSONL; fall back to a bare hostname per line.
            let (raw_host, source) = match serde_json::from_str::<SubfinderRecord>(line) {
                Ok(record) => (record.host, record.source),
                Err(_) => (line.to_owned(), None),
            };
            let Ok(host) = crate::targets::domain(&raw_host) else {
                continue; // malformed host — skip, keep the rest
            };
            if host == target || !seen.insert(host.clone()) {
                continue; // the apex itself, or a duplicate
            }
            let mut metadata = json!({"tool": "subfinder"});
            if let Some(source) = source {
                if source.len() <= 256 && !source.chars().any(char::is_control) {
                    metadata["subfinder_source"] = json!(source);
                }
            }
            // Only claim a subdomain relationship for genuine children of the
            // target; unrelated hosts are preserved without a false parent link.
            let is_child = host.ends_with(&suffix);
            discoveries.push(Discovery {
                asset_type: AssetType::Subdomain,
                value: host,
                source: is_child.then(|| target.to_owned()),
                relationship: is_child.then_some(RelationshipType::HasSubdomain),
                metadata,
            });
        }
        Ok(discoveries)
    }
}

// ---------------------------------------------------------------------------
// Native DNS provider (Phase 1B). Resolves hostnames to IP addresses using the
// injected resolver. It is built-in (no external tool) but participates fully in
// the provider architecture: provider run, evidence, events, provenance.
// ---------------------------------------------------------------------------

pub struct NativeDnsProvider {
    resolver: Arc<dyn DnsResolver>,
}

impl NativeDnsProvider {
    pub fn new(resolver: Arc<dyn DnsResolver>) -> Self {
        Self { resolver }
    }
}

#[derive(Serialize, Deserialize)]
struct DnsReport {
    provider: String,
    records: Vec<DnsHostRecord>,
}

#[derive(Serialize, Deserialize)]
struct DnsHostRecord {
    host: String,
    a: Vec<String>,
    aaaa: Vec<String>,
    outcome: DnsOutcome,
}

impl Provider for NativeDnsProvider {
    fn metadata(&self) -> ProviderMetadata {
        ProviderMetadata {
            id: "native_dns".into(),
            name: "Native DNS Resolver".into(),
            description: "Built-in A/AAAA resolution using the host's system resolver.".into(),
            version: "built-in".into(),
            risk_class: RiskClass::ActiveLowImpact,
            offline: true, // no external process; still active network I/O when live
            capabilities: vec![Capability::DnsResolution],
            // Target classification has no Subdomain variant (subdomains are
            // assets, not targets); a subdomain target classifies as a Domain or
            // Hostname. The provider resolves Subdomain/Hostname/Domain assets
            // from chain inputs regardless of the chain target type.
            supported_target_types: vec![TargetType::Domain, TargetType::Hostname],
        }
    }

    fn installation(&self, _tools: &ToolConfig) -> Installation {
        Installation::BuiltIn
    }

    fn execute(
        &self,
        target: &str,
        capability: Capability,
        inputs: &[Asset],
        ctx: &ProviderContext,
    ) -> Result<Execution> {
        let started_at = crate::now();
        // Resolve the hostname-like assets discovered earlier in this chain. Fall
        // back to the chain target itself when no such inputs exist (direct use).
        let mut hosts: Vec<String> = inputs
            .iter()
            .filter(|a| {
                matches!(
                    a.asset_type,
                    AssetType::Subdomain | AssetType::Hostname | AssetType::Domain
                )
            })
            .map(|a| a.canonical_identity.clone())
            .collect();
        hosts.sort();
        hosts.dedup();
        if hosts.is_empty() {
            hosts.push(target.to_owned());
        }
        let resolutions = self.resolver.resolve(&hosts, ctx.deadline, ctx.cancelled);
        if ctx.cancelled.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(CoreError::new("Cancelled", "DNS resolution cancelled."));
        }
        let records = resolutions
            .into_iter()
            .map(|r| DnsHostRecord {
                host: r.host,
                a: r.a.iter().map(|ip| ip.to_string()).collect(),
                aaaa: r.aaaa.iter().map(|ip| ip.to_string()).collect(),
                outcome: r.outcome,
            })
            .collect();
        let stdout = serde_json::to_vec_pretty(&DnsReport {
            provider: "native_dns".into(),
            records,
        })?;
        Ok(Execution {
            target: target.into(),
            capability,
            command: vec!["native_dns".into()],
            stdout,
            stderr: Vec::new(),
            exit_status: Some(0),
            pid: None,
            timed_out: false,
            started_at,
            ended_at: crate::now(),
        })
    }

    fn parse(&self, execution: &Execution) -> Result<Vec<Discovery>> {
        let report: DnsReport = serde_json::from_slice(&execution.stdout).map_err(|_| {
            CoreError::new("ProviderFailure", "Native DNS output is malformed.")
        })?;
        let mut discoveries = Vec::new();
        for record in report.records {
            // Normalize the source host once; addresses are already de-duplicated
            // per host by the resolver, and IP asset identities dedupe on upsert.
            let mut push = |value: &str, family: &str| {
                discoveries.push(Discovery {
                    asset_type: AssetType::IPAddress,
                    value: value.to_owned(),
                    source: Some(record.host.clone()),
                    relationship: Some(RelationshipType::ResolvesTo),
                    metadata: json!({
                        "tool": "native_dns",
                        "record_type": family,
                        "dns_outcome": record.outcome,
                    }),
                });
            };
            for ip in &record.a {
                push(ip, "A");
            }
            for ip in &record.aaaa {
                push(ip, "AAAA");
            }
        }
        Ok(discoveries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context<'a>(tools: &'a ToolConfig, cancelled: &'a AtomicBool) -> ProviderContext<'a> {
        ProviderContext {
            cancelled,
            deadline: Instant::now() + Duration::from_secs(10),
            tools,
        }
    }

    fn exec_with_stdout(target: &str, stdout: &[u8]) -> Execution {
        Execution {
            target: target.into(),
            capability: Capability::SubdomainDiscovery,
            command: vec!["subfinder".into()],
            stdout: stdout.to_vec(),
            stderr: Vec::new(),
            exit_status: Some(0),
            pid: None,
            timed_out: false,
            started_at: crate::now(),
            ended_at: crate::now(),
        }
    }

    #[test]
    fn synthetic_provider_is_passive_and_selected_by_capability() {
        let provider = ProviderRegistry::default()
            .named("synthetic", Capability::SubdomainDiscovery, TargetType::Domain)
            .unwrap();
        assert_eq!(provider.metadata().risk_class, RiskClass::Passive);
        assert_eq!(provider.metadata().id, "synthetic");
    }

    #[test]
    fn synthetic_output_is_structured_and_preserves_observations() {
        let provider = SyntheticDiscoveryProvider;
        let tools = ToolConfig::default();
        let cancelled = AtomicBool::new(false);
        let execution = provider
            .execute(
                "example.test",
                Capability::SubdomainDiscovery,
                &[],
                &context(&tools, &cancelled),
            )
            .unwrap();
        let discoveries = provider.parse(&execution).unwrap();
        assert_eq!(discoveries.len(), 4);
        assert_eq!(discoveries[2].value, "API.EXAMPLE.TEST");
    }

    #[test]
    fn synthetic_malformed_and_non_synthetic_input_fails() {
        assert!(SyntheticDiscoveryProvider
            .parse(&exec_with_stdout("example.test", b"not json"))
            .is_err());
        let tools = ToolConfig::default();
        let cancelled = AtomicBool::new(false);
        assert!(SyntheticDiscoveryProvider
            .execute(
                "example.com",
                Capability::SubdomainDiscovery,
                &[],
                &context(&tools, &cancelled)
            )
            .is_err());
    }

    #[test]
    fn subfinder_metadata_is_passive_domain_subdomain() {
        let metadata = SubfinderProvider.metadata();
        assert_eq!(metadata.id, "subfinder");
        assert_eq!(metadata.risk_class, RiskClass::Passive);
        assert!(!metadata.offline);
        assert_eq!(metadata.capabilities, vec![Capability::SubdomainDiscovery]);
        assert_eq!(metadata.supported_target_types, vec![TargetType::Domain]);
    }

    #[test]
    fn subfinder_reports_missing_when_absent() {
        let tools = ToolConfig::default(); // no override, unlikely to exist under a fake name
        // Force a definitely-missing tool by using an override to a nonexistent path.
        let mut missing = ToolConfig::default();
        missing
            .overrides
            .insert("subfinder".into(), "/nonexistent/subfinder".into());
        assert_eq!(SubfinderProvider.installation(&missing), Installation::Missing);
        let _ = tools;
    }

    #[test]
    fn subfinder_builds_safe_argument_array() {
        let args = SubfinderProvider::arguments("example.test");
        assert_eq!(args, vec!["-d", "example.test", "-silent", "-oJ"]);
    }

    #[test]
    fn subfinder_parses_jsonl_dedupes_and_normalizes() {
        let stdout = concat!(
            "{\"host\":\"api.example.test\"}\n",
            "{\"host\":\"API.EXAMPLE.TEST.\"}\n",   // dup after normalization
            "{\"host\":\"dev.example.test\",\"source\":\"crtsh\"}\n",
            "dev.example.test\n",                    // dup bare line
            "{\"host\":\"example.test\"}\n",         // apex, skipped
            "not-json-and-not-a-host !!\n",          // malformed, skipped
            "{\"host\":\"third-party.test\"}\n",     // unrelated, preserved w/o rel
        );
        let discoveries = SubfinderProvider
            .parse(&exec_with_stdout("example.test", stdout.as_bytes()))
            .unwrap();
        let values: Vec<_> = discoveries.iter().map(|d| d.value.as_str()).collect();
        assert_eq!(
            values,
            vec!["api.example.test", "dev.example.test", "third-party.test"]
        );
        // Children get a HasSubdomain relationship; unrelated hosts do not.
        assert_eq!(discoveries[0].relationship, Some(RelationshipType::HasSubdomain));
        assert_eq!(discoveries[0].source.as_deref(), Some("example.test"));
        assert_eq!(discoveries[2].relationship, None);
        assert_eq!(discoveries[2].source, None);
        assert_eq!(discoveries[1].metadata["subfinder_source"], json!("crtsh"));
    }

    #[test]
    fn subfinder_parses_empty_output_to_nothing() {
        let discoveries = SubfinderProvider
            .parse(&exec_with_stdout("example.test", b""))
            .unwrap();
        assert!(discoveries.is_empty());
    }

    // --- Native DNS provider ---

    fn dns_asset(kind: AssetType, identity: &str) -> Asset {
        Asset {
            id: crate::assets::Id::new_v4(),
            workspace_id: crate::assets::Id::new_v4(),
            asset_type: kind,
            canonical_identity: identity.into(),
            display_value: identity.into(),
            metadata: json!({}),
            first_seen: crate::now(),
            last_seen: crate::now(),
        }
    }

    #[test]
    fn native_dns_metadata_is_builtin_low_impact() {
        use crate::dns::StaticDnsResolver;
        let provider = NativeDnsProvider::new(Arc::new(StaticDnsResolver::new()));
        let metadata = provider.metadata();
        assert_eq!(metadata.id, "native_dns");
        assert_eq!(metadata.risk_class, RiskClass::ActiveLowImpact);
        assert_eq!(metadata.capabilities, vec![Capability::DnsResolution]);
        assert!(matches!(
            provider.installation(&ToolConfig::default()),
            Installation::BuiltIn
        ));
    }

    #[test]
    fn native_dns_resolves_dedupes_and_builds_resolves_to() {
        use crate::dns::StaticDnsResolver;
        let resolver = StaticDnsResolver::new()
            .with(
                "api.example.test",
                &["192.0.2.10".parse().unwrap(), "192.0.2.10".parse().unwrap()], // duplicate
                &["2001:db8::10".parse().unwrap()],
            )
            .with("dev.example.test", &["192.0.2.11".parse().unwrap()], &[]);
        let provider = NativeDnsProvider::new(Arc::new(resolver));
        let tools = ToolConfig::default();
        let cancelled = AtomicBool::new(false);
        let inputs = vec![
            dns_asset(AssetType::Subdomain, "api.example.test"),
            dns_asset(AssetType::Subdomain, "dev.example.test"),
        ];
        let execution = provider
            .execute("example.test", Capability::DnsResolution, &inputs, &context(&tools, &cancelled))
            .unwrap();
        let discoveries = provider.parse(&execution).unwrap();
        // api -> 192.0.2.10 (deduped) + 2001:db8::10 ; dev -> 192.0.2.11  => 3
        assert_eq!(discoveries.len(), 3);
        assert!(discoveries
            .iter()
            .all(|d| d.asset_type == AssetType::IPAddress
                && d.relationship == Some(RelationshipType::ResolvesTo)));
        assert_eq!(
            discoveries.iter().filter(|d| d.source.as_deref() == Some("api.example.test")).count(),
            2
        );
    }

    #[test]
    fn native_dns_no_records_yields_no_discoveries() {
        use crate::dns::{DnsOutcome, StaticDnsResolver};
        let resolver = StaticDnsResolver::new().with_outcome("api.example.test", DnsOutcome::NoRecords);
        let provider = NativeDnsProvider::new(Arc::new(resolver));
        let tools = ToolConfig::default();
        let cancelled = AtomicBool::new(false);
        let inputs = vec![dns_asset(AssetType::Subdomain, "api.example.test")];
        let execution = provider
            .execute("example.test", Capability::DnsResolution, &inputs, &context(&tools, &cancelled))
            .unwrap();
        assert!(provider.parse(&execution).unwrap().is_empty());
    }

    #[test]
    fn native_dns_falls_back_to_target_when_no_host_inputs() {
        use crate::dns::StaticDnsResolver;
        let resolver = StaticDnsResolver::new().with("example.test", &["192.0.2.1".parse().unwrap()], &[]);
        let provider = NativeDnsProvider::new(Arc::new(resolver));
        let tools = ToolConfig::default();
        let cancelled = AtomicBool::new(false);
        let execution = provider
            .execute("example.test", Capability::DnsResolution, &[], &context(&tools, &cancelled))
            .unwrap();
        let discoveries = provider.parse(&execution).unwrap();
        assert_eq!(discoveries.len(), 1);
        assert_eq!(discoveries[0].value, "192.0.2.1");
        assert_eq!(discoveries[0].source.as_deref(), Some("example.test"));
    }

    #[test]
    fn native_dns_cancellation_is_reported() {
        use crate::dns::StaticDnsResolver;
        let resolver = StaticDnsResolver::new().with("api.example.test", &["192.0.2.10".parse().unwrap()], &[]);
        let provider = NativeDnsProvider::new(Arc::new(resolver));
        let tools = ToolConfig::default();
        let cancelled = AtomicBool::new(true);
        let inputs = vec![dns_asset(AssetType::Subdomain, "api.example.test")];
        let error = provider
            .execute("example.test", Capability::DnsResolution, &inputs, &context(&tools, &cancelled))
            .unwrap_err();
        assert_eq!(error.code, "Cancelled");
    }
}
