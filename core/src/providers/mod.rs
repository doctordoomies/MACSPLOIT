use crate::{
    assets::{Asset, AssetType, Discovery, RelationshipType},
    dns::{DnsOutcome, DnsResolver},
    error::{CoreError, Result},
    process::{self, Installation, ToolConfig},
    targets::TargetType,
    web::{WebResponse, WebTransport},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    sync::{atomic::AtomicBool, Arc},
    time::{Duration, Instant},
};

mod user_scanner;
pub use user_scanner::UserScannerProvider;

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
pub enum NetworkActivity {
    None,
    Network,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Capability {
    SubdomainDiscovery,
    DnsResolution,
    PortDiscovery,
    ServiceFingerprinting,
    HttpProbing,
    WebCrawling,
    WebAnalysis,
    ContentDiscovery,
    /// OSINT: public account/profile presence for an explicit Username subject.
    UsernameOsint,
    /// OSINT: public registration/profile presence for an explicit Email subject.
    EmailOsint,
}

impl Capability {
    /// OSINT capabilities operate on an identifier subject (username/email), not a
    /// workspace host, and query third-party public platforms chosen by the provider.
    pub fn is_osint(self) -> bool {
        matches!(self, Self::UsernameOsint | Self::EmailOsint)
    }
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
    /// Whether normal provider execution can perform network I/O. This is separate
    /// from built-in/external process state, which comes from Installation.
    pub network_activity: NetworkActivity,
}

/// Provider metadata paired with its live installation state, for the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderStatus {
    #[serde(flatten)]
    pub metadata: ProviderMetadata,
    /// Deprecated protocol-v1 compatibility alias derived from network_activity.
    pub offline: bool,
    pub installation: Installation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup: Option<ProviderSetup>,
    /// Which reviewed install methods MACSPLOIT offers for this provider. The core
    /// matrix is authoritative; the UI uses this only to decide which buttons to
    /// show (it never chooses formulas, URLs, or artifacts itself).
    #[serde(default)]
    pub install: ProviderInstallInfo,
}

/// Reviewed install-method availability for one provider, derived from the typed
/// installer matrix. Presentation metadata only — installation is always enforced
/// and performed by the Rust core.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderInstallInfo {
    /// A `brew install <reviewed formula>` method is available.
    pub homebrew: bool,
    /// A verified app-managed direct download is available (false for Nmap).
    pub managed_download: bool,
    /// The provider's official installer/download page, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub official_installer_url: Option<String>,
}

/// Static, provider-owned help. Consumers may display/copy it, never execute it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderSetup {
    pub install_command: Option<String>,
    pub homepage: Option<String>,
    pub documentation: Option<String>,
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
    /// Additional bounded structured outputs the tool wrote outside stdout (e.g. a
    /// JSON report file). Each is persisted as its own hashed evidence record before
    /// parsing and referenced from the execution envelope.
    pub artifacts: Vec<ExecutionArtifact>,
    /// True when the run was cancelled after the process started. The orchestrator
    /// still persists the captured evidence, then reports the chain as cancelled.
    pub cancelled: bool,
}

/// A bounded structured output captured from a provider run.
#[derive(Debug, Clone)]
pub struct ExecutionArtifact {
    /// Stable short name (e.g. `user_scanner_json`).
    pub name: String,
    /// The exact bytes captured (empty when absent or over the bound).
    pub bytes: Vec<u8>,
    /// Observed size on disk, when known (may exceed `bytes.len()` when over bound).
    pub observed_bytes: Option<u64>,
    /// True when the artifact exceeded its bound and was not captured.
    pub over_limit: bool,
}

/// What a provider's parser produced: discoveries plus whether the run's results
/// are partial (some checks failed/were dropped) and an optional bounded summary
/// for the live console and run results.
#[derive(Debug, Clone, Default)]
pub struct ParsedOutput {
    pub discoveries: Vec<Discovery>,
    pub partial: bool,
    pub summary: Option<serde_json::Value>,
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
    /// Workspace scope entries, so a provider can scope-check destinations it
    /// discovers during execution (e.g. redirect hops).
    pub scope: &'a [String],
    /// Per-run options (e.g. the content-discovery wordlist path). Null when unused.
    pub options: &'a serde_json::Value,
}

pub trait Provider: Send + Sync {
    fn metadata(&self) -> ProviderMetadata;
    fn setup(&self) -> Option<ProviderSetup> {
        None
    }
    /// Report whether the provider's backing tool is available. Built-in
    /// providers return Installation::BuiltIn.
    fn installation(&self, tools: &ToolConfig) -> Installation;
    /// Maximum wall-clock time for one execution. Fast providers keep the default;
    /// heavier active tools (e.g. Nmap) override it.
    fn timeout(&self) -> Duration {
        Duration::from_secs(30)
    }
    fn execute(
        &self,
        target: &str,
        capability: Capability,
        inputs: &[Asset],
        ctx: &ProviderContext,
    ) -> Result<Execution>;
    fn parse(&self, execution: &Execution) -> Result<Vec<Discovery>>;
    /// Parse with run-level detail. Providers that can report partial results or a
    /// run summary override this; the default wraps [`Provider::parse`].
    fn parse_outcome(&self, execution: &Execution) -> Result<ParsedOutput> {
        Ok(ParsedOutput {
            discoveries: self.parse(execution)?,
            partial: false,
            summary: None,
        })
    }
}

#[derive(Clone)]
pub struct ProviderRegistry {
    providers: Vec<Arc<dyn Provider>>,
}

impl ProviderRegistry {
    /// Build the registry with an explicit DNS resolver (injected in tests). The
    /// web-analysis transport is selected from the environment.
    pub fn new(resolver: Arc<dyn DnsResolver>) -> Self {
        Self::with_transports(resolver, crate::web::transport_from_env())
    }

    /// Build the registry with explicit DNS and web transports (injected in tests).
    pub fn with_transports(resolver: Arc<dyn DnsResolver>, web: Arc<dyn WebTransport>) -> Self {
        Self {
            providers: vec![
                Arc::new(SyntheticDiscoveryProvider),
                Arc::new(SubfinderProvider),
                Arc::new(NativeDnsProvider::new(resolver)),
                Arc::new(NmapProvider),
                Arc::new(HttpxProvider),
                Arc::new(KatanaProvider),
                Arc::new(NativeHttpProvider::new(web)),
                Arc::new(FfufProvider),
                Arc::new(UserScannerProvider),
            ],
        }
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::with_transports(
            Arc::new(crate::dns::SystemDnsResolver::default()),
            Arc::new(crate::web::UreqTransport::default()),
        )
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

    /// Fetch a provider by its stable identifier and verify it advertises the
    /// requested capability. A pinned provider operates on the chain's input
    /// assets (whose types differ from the chain target — e.g. Nmap consumes
    /// IPAddress assets while the chain target is a Domain), so the target type is
    /// not re-checked here; the stage pin is the authorization.
    pub fn named(&self, id: &str, capability: Capability) -> Result<Arc<dyn Provider>> {
        let provider = self
            .providers
            .iter()
            .find(|provider| provider.metadata().id == id)
            .cloned()
            .ok_or_else(|| {
                CoreError::new(
                    "ProviderFailure",
                    "The requested provider is not registered.",
                )
            })?;
        if !provider.metadata().capabilities.contains(&capability) {
            return Err(CoreError::new(
                "ProviderFailure",
                "The pinned provider does not offer this capability.",
            ));
        }
        Ok(provider)
    }

    /// Resolve the provider for an OSINT run: the explicitly requested provider id
    /// when given, otherwise the first registered provider for the capability. The
    /// provider must advertise both the capability and the subject's target type.
    pub fn osint_provider(
        &self,
        capability: Capability,
        target_type: TargetType,
        requested: Option<&str>,
    ) -> Result<Arc<dyn Provider>> {
        let compatible = |provider: &Arc<dyn Provider>| {
            let metadata = provider.metadata();
            metadata.capabilities.contains(&capability)
                && metadata.supported_target_types.contains(&target_type)
        };
        match requested {
            Some(id) => {
                let provider = self
                    .providers
                    .iter()
                    .find(|provider| provider.metadata().id == id)
                    .ok_or_else(|| {
                        CoreError::new(
                            "ProviderUnsupported",
                            "The requested OSINT provider is not registered.",
                        )
                    })?;
                if !compatible(provider) {
                    return Err(CoreError::new(
                        "ProviderUnsupported",
                        "The requested provider does not support this OSINT workflow and target type.",
                    ));
                }
                Ok(provider.clone())
            }
            None => self
                .providers
                .iter()
                .find(|p| compatible(p))
                .cloned()
                .ok_or_else(|| {
                    CoreError::new(
                        "ProviderUnsupported",
                        "No registered provider supports this OSINT workflow.",
                    )
                }),
        }
    }

    pub fn metadata(&self) -> Vec<ProviderMetadata> {
        self.providers.iter().map(|p| p.metadata()).collect()
    }

    pub fn status(&self, tools: &ToolConfig) -> Vec<ProviderStatus> {
        self.providers
            .iter()
            .map(|provider| {
                let metadata = provider.metadata();
                let install = match crate::install::options(&metadata.id) {
                    Some(opts) => ProviderInstallInfo {
                        homebrew: opts.homebrew_formula.is_some(),
                        managed_download: opts.managed_download_supported,
                        official_installer_url: opts.official_installer_url.map(str::to_owned),
                    },
                    None => ProviderInstallInfo::default(),
                };
                ProviderStatus {
                    offline: metadata.network_activity == NetworkActivity::None,
                    installation: provider.installation(tools),
                    setup: provider.setup(),
                    install,
                    metadata,
                }
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
            network_activity: NetworkActivity::None,
            capabilities: vec![
                Capability::SubdomainDiscovery,
                Capability::DnsResolution,
                Capability::ServiceFingerprinting,
            ],
            supported_target_types: vec![TargetType::Domain],
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
                observation: None,
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
            // The synthetic provider does not model port discovery or HTTP probing.
            Capability::PortDiscovery
            | Capability::HttpProbing
            | Capability::WebCrawling
            | Capability::WebAnalysis
            | Capability::ContentDiscovery
            | Capability::UsernameOsint
            | Capability::EmailOsint => {}
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
            artifacts: Vec::new(),
            cancelled: false,
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
        vec!["-d".into(), target.into(), "-silent".into(), "-oJ".into()]
    }
}

impl Provider for SubfinderProvider {
    fn setup(&self) -> Option<ProviderSetup> {
        Some(ProviderSetup {
            install_command: Some("brew install subfinder".into()),
            homepage: Some("https://github.com/projectdiscovery/subfinder".into()),
            documentation: Some("https://docs.projectdiscovery.io/tools/subfinder/overview".into()),
        })
    }

    fn metadata(&self) -> ProviderMetadata {
        ProviderMetadata {
            id: "subfinder".into(),
            name: "Subfinder".into(),
            description:
                "Passive subdomain enumeration via the external ProjectDiscovery subfinder tool."
                    .into(),
            version: "external".into(),
            risk_class: RiskClass::Passive,
            network_activity: NetworkActivity::Network,
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
            Ok(outcome) if outcome.timed_out || outcome.exit_status != Some(0) => {
                Installation::ExecutionError {
                    message: "The provider version probe failed or timed out.".into(),
                }
            }
            Ok(outcome) => {
                let mut text = String::from_utf8_lossy(&outcome.stdout).into_owned();
                text.push('\n');
                text.push_str(&String::from_utf8_lossy(&outcome.stderr));
                // Surface an unknown version explicitly rather than claiming one.
                let version = process::scan_version(&text).unwrap_or_else(|| "unknown".into());
                Installation::Installed {
                    version,
                    path: Some(executable),
                }
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
            artifacts: Vec::new(),
            cancelled: false,
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
                observation: None,
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
    #[serde(default)]
    reverse: Vec<DnsPtrRecord>,
}

#[derive(Serialize, Deserialize)]
struct DnsHostRecord {
    host: String,
    a: Vec<String>,
    aaaa: Vec<String>,
    outcome: DnsOutcome,
}

#[derive(Serialize, Deserialize)]
struct DnsPtrRecord {
    ip: String,
    names: Vec<String>,
    outcome: DnsOutcome,
}

/// Decide what to resolve for native DNS given chain inputs and the target. Forward
/// lookups come from hostname-like inputs (Domain Recon subdomains); when there are
/// none (direct DNS Recon) the target drives it: a URL contributes its host (forward
/// for a hostname, reverse for an IP literal), an IP target is a reverse lookup, and a
/// domain/hostname target is a forward lookup.
fn native_dns_plan(inputs: &[Asset], target: &str) -> (Vec<String>, Vec<std::net::IpAddr>) {
    let mut forward: Vec<String> = inputs
        .iter()
        .filter(|a| {
            matches!(
                a.asset_type,
                AssetType::Subdomain | AssetType::Hostname | AssetType::Domain
            )
        })
        .map(|a| a.canonical_identity.clone())
        .collect();
    forward.sort();
    forward.dedup();
    if !forward.is_empty() {
        return (forward, Vec::new());
    }
    // Direct DNS Recon: classify the target (extract the host for a URL).
    let host = if let Ok(url) = url::Url::parse(target) {
        url.host_str()
            .map(|h| h.trim_matches(['[', ']']).to_owned())
            .unwrap_or_else(|| target.to_owned())
    } else {
        target.to_owned()
    };
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        (Vec::new(), vec![ip])
    } else {
        (vec![host], Vec::new())
    }
}

impl Provider for NativeDnsProvider {
    fn metadata(&self) -> ProviderMetadata {
        ProviderMetadata {
            id: "native_dns".into(),
            name: "Native DNS Resolver".into(),
            description:
                "Built-in DNS: A/AAAA forward resolution, and PTR reverse lookup for IP targets."
                    .into(),
            version: "built-in".into(),
            risk_class: RiskClass::ActiveLowImpact,
            network_activity: NetworkActivity::Network,
            capabilities: vec![Capability::DnsResolution],
            // Forward for Domain/Hostname (and URL hostnames); reverse PTR for an
            // IPAddress target or a URL whose host is an IP literal. The provider also
            // resolves Subdomain/Hostname/Domain assets from chain inputs.
            supported_target_types: vec![
                TargetType::Domain,
                TargetType::Hostname,
                TargetType::IPAddress,
                TargetType::URL,
            ],
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
        if ctx.cancelled.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(CoreError::new("Cancelled", "DNS resolution cancelled."));
        }
        let started_at = crate::now();
        // Decide forward hosts and reverse IPs from inputs + target (see native_dns_plan).
        let (hosts, reverse_ips) = native_dns_plan(inputs, target);
        let resolutions = if hosts.is_empty() {
            Vec::new()
        } else {
            self.resolver.resolve(&hosts, ctx.deadline, ctx.cancelled)
        };
        let reverse = if reverse_ips.is_empty() {
            Vec::new()
        } else {
            self.resolver
                .reverse(&reverse_ips, ctx.deadline, ctx.cancelled)
        };
        let records = resolutions
            .into_iter()
            .map(|r| DnsHostRecord {
                host: r.host,
                a: r.a.iter().map(|ip| ip.to_string()).collect(),
                aaaa: r.aaaa.iter().map(|ip| ip.to_string()).collect(),
                outcome: r.outcome,
            })
            .collect();
        let reverse = reverse
            .into_iter()
            .map(|r| DnsPtrRecord {
                ip: r.ip.to_string(),
                names: r.names,
                outcome: r.outcome,
            })
            .collect();
        let stdout = serde_json::to_vec_pretty(&DnsReport {
            provider: "native_dns".into(),
            records,
            reverse,
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
            artifacts: Vec::new(),
            cancelled: false,
        })
    }

    fn parse(&self, execution: &Execution) -> Result<Vec<Discovery>> {
        let report: DnsReport = serde_json::from_slice(&execution.stdout)
            .map_err(|_| CoreError::new("ProviderFailure", "Native DNS output is malformed."))?;
        let mut discoveries = Vec::new();
        for record in report.records {
            // A hostname extracted from a URL is not yet an asset. Persist that
            // context before its A/AAAA relationship; the run retains the original URL.
            if url::Url::parse(&execution.target).is_ok() {
                discoveries.push(Discovery {
                    asset_type: AssetType::Hostname,
                    value: record.host.clone(),
                    source: None,
                    relationship: None,
                    observation: None,
                    metadata: json!({"tool":"native_dns", "dns_outcome":record.outcome}),
                });
            }
            // Normalize the source host once; addresses are already de-duplicated
            // per host by the resolver, and IP asset identities dedupe on upsert.
            let mut push = |value: &str, family: &str| {
                discoveries.push(Discovery {
                    asset_type: AssetType::IPAddress,
                    value: value.to_owned(),
                    source: Some(record.host.clone()),
                    relationship: Some(RelationshipType::ResolvesTo),
                    observation: None,
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
        // Reverse (PTR): each PTR name is a Hostname asset linked from the IP by a
        // ptr_record relationship. This is a PTR observation only (not forward-confirmed).
        for record in report.reverse {
            // Ensure the looked-up IP exists as an asset so the PTR name can link to it
            // (a URL-with-IP target has no IPAddress asset otherwise).
            discoveries.push(Discovery {
                asset_type: AssetType::IPAddress,
                value: record.ip.clone(),
                source: None,
                relationship: None,
                observation: None,
                metadata: json!({ "tool": "native_dns", "reverse_lookup": true, "dns_outcome": record.outcome }),
            });
            for name in &record.names {
                let Ok(name) = crate::targets::domain(name) else {
                    continue;
                };
                discoveries.push(Discovery {
                    asset_type: AssetType::Hostname,
                    value: name.clone(),
                    source: Some(record.ip.clone()),
                    relationship: Some(RelationshipType::PtrRecord),
                    observation: None,
                    metadata: json!({
                        "tool": "native_dns",
                        "record_type": "PTR",
                        "dns_outcome": record.outcome,
                    }),
                });
            }
        }
        Ok(discoveries)
    }
}

// ---------------------------------------------------------------------------
// Nmap provider (Phase 1C; first ACTIVE provider). Turns in-scope IPAddress
// assets into Port and Service assets via a conservative, unprivileged scan.
// Executes through the process supervisor with XML output; no NSE, no root.
// ---------------------------------------------------------------------------

pub struct NmapProvider;

/// Remove a single leading `<!DOCTYPE ...>` declaration that has no internal subset
/// (`[ ... ]`). Real nmap emits exactly `<!DOCTYPE nmaprun>`, which a non-validating,
/// DTD-rejecting parser would otherwise refuse. A DOCTYPE containing an internal
/// subset (the entity-expansion / billion-laughs vector) is deliberately left intact
/// so the parser still rejects it; entity expansion therefore stays disabled.
fn strip_simple_doctype(xml: &str) -> std::borrow::Cow<'_, str> {
    if let Some(start) = xml.find("<!DOCTYPE") {
        if let Some(rel_end) = xml[start..].find('>') {
            let decl = &xml[start..start + rel_end + 1];
            if !decl.contains('[') {
                let mut out = String::with_capacity(xml.len());
                out.push_str(&xml[..start]);
                out.push_str(&xml[start + rel_end + 1..]);
                return std::borrow::Cow::Owned(out);
            }
        }
    }
    std::borrow::Cow::Borrowed(xml)
}

/// Separator placed between multiple nmap XML documents in one evidence blob
/// (one document per address family). The parser splits on it.
const NMAP_XML_DELIM: &str = "\n<!--MACSPLOIT-NMAP-DOC-->\n";
const NMAP_STDOUT_CAP: usize = 512 * 1024;
const NMAP_STDERR_CAP: usize = 64 * 1024;

impl NmapProvider {
    /// Conservative, unprivileged discovery profile: TCP connect scan (`-sT`, no
    /// root), service/version detection (`-sV`), a bounded top-100 port set, and
    /// XML to stdout (`-oX -`). No host-discovery skip, no NSE, no aggressive
    /// timing or OS detection. `-6` is added for an IPv6 batch.
    fn arguments(ipv6: bool, targets: &[String]) -> Vec<String> {
        let mut args = vec![
            "-sT".into(),
            "-sV".into(),
            "--top-ports".into(),
            "100".into(),
            "-oX".into(),
            "-".into(),
        ];
        if ipv6 {
            args.push("-6".into());
        }
        args.extend(targets.iter().cloned());
        args
    }
}

impl Provider for NmapProvider {
    fn setup(&self) -> Option<ProviderSetup> {
        Some(ProviderSetup {
            install_command: Some("brew install nmap".into()),
            homepage: Some("https://nmap.org".into()),
            documentation: Some("https://nmap.org/book/man.html".into()),
        })
    }

    fn metadata(&self) -> ProviderMetadata {
        ProviderMetadata {
            id: "nmap".into(),
            name: "Nmap".into(),
            description:
                "Active port and service discovery via the external Nmap tool (unprivileged, no NSE)."
                    .into(),
            version: "external".into(),
            risk_class: RiskClass::Active,
            network_activity: NetworkActivity::Network,
            capabilities: vec![Capability::PortDiscovery, Capability::ServiceFingerprinting],
            supported_target_types: vec![TargetType::IPAddress],
        }
    }

    fn installation(&self, tools: &ToolConfig) -> Installation {
        let Some(executable) = tools.locate("nmap") else {
            return Installation::Missing;
        };
        let cancelled = AtomicBool::new(false);
        match process::run(
            &executable,
            &["--version".into()],
            &cancelled,
            Instant::now() + Duration::from_secs(5),
            NMAP_STDERR_CAP,
            NMAP_STDERR_CAP,
        ) {
            Ok(outcome) if outcome.timed_out || outcome.exit_status != Some(0) => {
                Installation::ExecutionError {
                    message: "The provider version probe failed or timed out.".into(),
                }
            }
            Ok(outcome) => {
                let mut text = String::from_utf8_lossy(&outcome.stdout).into_owned();
                text.push('\n');
                text.push_str(&String::from_utf8_lossy(&outcome.stderr));
                let version = process::scan_version(&text).unwrap_or_else(|| "unknown".into());
                Installation::Installed {
                    version,
                    path: Some(executable),
                }
            }
            Err(error) => Installation::ExecutionError {
                message: error.message,
            },
        }
    }

    fn timeout(&self) -> Duration {
        // Active scans legitimately take longer than passive discovery.
        Duration::from_secs(120)
    }

    fn execute(
        &self,
        target: &str,
        capability: Capability,
        inputs: &[Asset],
        ctx: &ProviderContext,
    ) -> Result<Execution> {
        let started_at = crate::now();
        // Scan only in-scope IP assets (the orchestrator has already filtered
        // inputs to workspace scope, so an out-of-scope resolved IP never reaches
        // an active tool). Partition by family: nmap cannot mix IPv4 and IPv6.
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for asset in inputs
            .iter()
            .filter(|a| a.asset_type == AssetType::IPAddress)
        {
            match asset.canonical_identity.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(_)) => v4.push(asset.canonical_identity.clone()),
                Ok(std::net::IpAddr::V6(_)) => v6.push(asset.canonical_identity.clone()),
                Err(_) => {}
            }
        }
        v4.sort();
        v4.dedup();
        v6.sort();
        v6.dedup();

        if v4.is_empty() && v6.is_empty() {
            // Nothing in scope to scan; a clean, empty run (not a failure).
            return Ok(Execution {
                target: target.into(),
                capability,
                command: vec!["nmap".into(), "(no in-scope IP targets)".into()],
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_status: Some(0),
                pid: None,
                timed_out: false,
                started_at,
                ended_at: crate::now(),
                artifacts: Vec::new(),
                cancelled: false,
            });
        }

        let executable = ctx.tools.locate("nmap").ok_or_else(|| {
            CoreError::new(
                "ProviderMissing",
                "Nmap is not installed. Install it manually to run active discovery.",
            )
        })?;

        let mut command = vec![executable.to_string_lossy().into_owned()];
        let mut xml_docs: Vec<String> = Vec::new();
        let mut stderr_all = Vec::new();
        let mut exit_status = Some(0);
        let mut timed_out = false;
        for (ipv6, targets) in [(false, &v4), (true, &v6)] {
            if targets.is_empty() {
                continue;
            }
            let args = Self::arguments(ipv6, targets);
            let outcome = process::run(
                &executable,
                &args,
                ctx.cancelled,
                ctx.deadline,
                NMAP_STDOUT_CAP,
                NMAP_STDERR_CAP,
            )?;
            if outcome.cancelled {
                return Err(CoreError::new("Cancelled", "Nmap scan cancelled."));
            }
            command.extend(args);
            xml_docs.push(String::from_utf8_lossy(&outcome.stdout).into_owned());
            stderr_all.extend_from_slice(&outcome.stderr);
            if outcome.timed_out {
                timed_out = true;
            }
            if outcome.exit_status != Some(0) {
                exit_status = outcome.exit_status.or(Some(1));
            }
        }

        Ok(Execution {
            target: target.into(),
            capability,
            command,
            stdout: xml_docs.join(NMAP_XML_DELIM).into_bytes(),
            stderr: stderr_all,
            exit_status,
            pid: None,
            timed_out,
            started_at,
            ended_at: crate::now(),
            artifacts: Vec::new(),
            cancelled: false,
        })
    }

    fn parse(&self, execution: &Execution) -> Result<Vec<Discovery>> {
        let text = String::from_utf8_lossy(&execution.stdout);
        let mut discoveries = Vec::new();
        let mut any_document = false;
        for chunk in text.split(NMAP_XML_DELIM) {
            let chunk = chunk.trim();
            if chunk.is_empty() {
                continue;
            }
            any_document = true;
            // Real nmap emits a `<!DOCTYPE nmaprun>` (plus an XSL stylesheet PI and
            // comments). Remove only a *simple* DOCTYPE with no internal subset so the
            // document parses, while keeping entity expansion fully disabled: a DOCTYPE
            // that carries an internal subset (`[ ... ]`, the billion-laughs / custom
            // entity vector) is left in place and still rejected by roxmltree.
            let sanitized = strip_simple_doctype(chunk);
            let document = roxmltree::Document::parse(&sanitized)
                .map_err(|_| CoreError::new("ProviderFailure", "Nmap XML output is malformed."))?;
            for host in document.descendants().filter(|n| n.has_tag_name("host")) {
                // The reportable address is the ipv4/ipv6 address element.
                let Some(address) = host
                    .children()
                    .filter(|n| n.has_tag_name("address"))
                    .find_map(|n| {
                        let kind = n.attribute("addrtype").unwrap_or("");
                        if kind.starts_with("ip") {
                            n.attribute("addr")
                        } else {
                            None
                        }
                    })
                else {
                    continue;
                };
                for port in host.descendants().filter(|n| n.has_tag_name("port")) {
                    let protocol = port.attribute("protocol").unwrap_or("tcp");
                    let Some(portid) = port.attribute("portid") else {
                        continue;
                    };
                    let state = port
                        .children()
                        .find(|n| n.has_tag_name("state"))
                        .and_then(|n| n.attribute("state"))
                        .unwrap_or("");
                    // Only model reportable open states; raw XML retains everything.
                    if state != "open" && state != "open|filtered" {
                        continue;
                    }
                    let port_value = format!("{address}/{protocol}/{portid}");
                    discoveries.push(Discovery {
                        asset_type: AssetType::Port,
                        value: port_value.clone(),
                        source: Some(address.to_owned()),
                        relationship: Some(RelationshipType::Exposes),
                        observation: None,
                        metadata: json!({
                            "tool": "nmap",
                            "host": address,
                            "port": portid,
                            "protocol": protocol,
                            "state": state,
                        }),
                    });
                    if let Some(service) = port.children().find(|n| n.has_tag_name("service")) {
                        let name = service.attribute("name").unwrap_or("unknown");
                        let mut metadata = json!({
                            "tool": "nmap",
                            "host": address,
                            "protocol": protocol,
                            "name": name,
                        });
                        for (attr, key) in [
                            ("product", "product"),
                            ("version", "version"),
                            ("extrainfo", "extrainfo"),
                            ("tunnel", "tunnel"),
                        ] {
                            if let Some(value) = service.attribute(attr) {
                                metadata[key] = json!(value);
                            }
                        }
                        discoveries.push(Discovery {
                            asset_type: AssetType::Service,
                            value: format!("{port_value}/{name}"),
                            source: Some(port_value.clone()),
                            relationship: Some(RelationshipType::Serves),
                            observation: None,
                            metadata,
                        });
                    }
                }
            }
        }
        if !any_document {
            // No hosts scanned (e.g. nothing in scope) — a clean empty result.
            return Ok(discoveries);
        }
        Ok(discoveries)
    }
}

// ---------------------------------------------------------------------------
// HTTPX provider (Phase 1D). Probes discovered HTTP/HTTPS services and produces
// Website and Technology assets. Low-impact active: it makes ordinary,
// non-intrusive HTTP requests to in-scope hosts (no fuzzing, no exploitation).
// ---------------------------------------------------------------------------

pub struct HttpxProvider;

const HTTPX_STDOUT_CAP: usize = 512 * 1024;
const HTTPX_STDERR_CAP: usize = 64 * 1024;

/// One JSONL record emitted by `httpx -json`. Fields are all optional except a
/// URL; unknown fields are ignored.
#[derive(Deserialize)]
struct HttpxRecord {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    input: Option<String>,
    #[serde(default)]
    status_code: Option<i64>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    webserver: Option<String>,
    #[serde(default)]
    content_length: Option<i64>,
    #[serde(default)]
    location: Option<String>,
    // The owning host is derived from the normalized probe URL (bracket-aware for
    // IPv6), so httpx's own `host` field is intentionally not consumed here.
    #[serde(default)]
    tech: Vec<String>,
}

impl HttpxProvider {
    /// Format a host for a URL authority: an IPv6 literal is wrapped in brackets
    /// (`2001:db8::10` -> `[2001:db8::10]`) so the resulting URL is valid; IPv4
    /// literals and hostnames are returned unchanged. Already-bracketed input is
    /// left as-is so normalized values are never double-bracketed.
    fn url_host(host: &str) -> String {
        if host.starts_with('[') || host.parse::<std::net::Ipv6Addr>().is_err() {
            host.to_string()
        } else {
            format!("[{host}]")
        }
    }

    /// Build the probe URL list from discovered HTTP/HTTPS Service assets. A
    /// Service canonical identity is `<ip>/<proto>/<port>/<name>`.
    fn urls_from_services(inputs: &[Asset]) -> Vec<String> {
        let mut urls = Vec::new();
        for asset in inputs.iter().filter(|a| a.asset_type == AssetType::Service) {
            let parts: Vec<&str> = asset.canonical_identity.split('/').collect();
            if parts.len() < 4 {
                continue;
            }
            let (host, port, name) = (parts[0], parts[2], parts[3]);
            let scheme = if name.starts_with("https") {
                "https"
            } else if name.starts_with("http") {
                "http"
            } else {
                continue;
            };
            let url = format!("{scheme}://{}:{port}", Self::url_host(host));
            if !urls.contains(&url) {
                urls.push(url);
            }
        }
        urls
    }
}

impl Provider for HttpxProvider {
    fn setup(&self) -> Option<ProviderSetup> {
        Some(ProviderSetup {
            install_command: Some("brew install httpx".into()),
            homepage: Some("https://github.com/projectdiscovery/httpx".into()),
            documentation: Some("https://docs.projectdiscovery.io/tools/httpx/overview".into()),
        })
    }

    fn metadata(&self) -> ProviderMetadata {
        ProviderMetadata {
            id: "httpx".into(),
            name: "HTTPX".into(),
            description:
                "Low-impact HTTP/HTTPS probing of discovered web services via the external httpx tool."
                    .into(),
            version: "external".into(),
            risk_class: RiskClass::ActiveLowImpact,
            network_activity: NetworkActivity::Network,
            capabilities: vec![Capability::HttpProbing],
            supported_target_types: vec![TargetType::Domain, TargetType::IPAddress],
        }
    }

    fn installation(&self, tools: &ToolConfig) -> Installation {
        let Some(executable) = tools.locate("httpx") else {
            return Installation::Missing;
        };
        let cancelled = AtomicBool::new(false);
        match process::run(
            &executable,
            &["-version".into()],
            &cancelled,
            Instant::now() + Duration::from_secs(5),
            HTTPX_STDERR_CAP,
            HTTPX_STDERR_CAP,
        ) {
            Ok(outcome) if outcome.timed_out || outcome.exit_status != Some(0) => {
                Installation::ExecutionError {
                    message: "The provider version probe failed or timed out.".into(),
                }
            }
            Ok(outcome) => {
                let mut text = String::from_utf8_lossy(&outcome.stdout).into_owned();
                text.push('\n');
                text.push_str(&String::from_utf8_lossy(&outcome.stderr));
                let version = process::scan_version(&text).unwrap_or_else(|| "unknown".into());
                Installation::Installed {
                    version,
                    path: Some(executable),
                }
            }
            Err(error) => Installation::ExecutionError {
                message: error.message,
            },
        }
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(60)
    }

    fn execute(
        &self,
        target: &str,
        capability: Capability,
        inputs: &[Asset],
        ctx: &ProviderContext,
    ) -> Result<Execution> {
        let started_at = crate::now();
        let urls = Self::urls_from_services(inputs);
        if urls.is_empty() {
            return Ok(Execution {
                target: target.into(),
                capability,
                command: vec!["httpx".into(), "(no in-scope web services)".into()],
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_status: Some(0),
                pid: None,
                timed_out: false,
                started_at,
                ended_at: crate::now(),
                artifacts: Vec::new(),
                cancelled: false,
            });
        }
        let executable = ctx.tools.locate("httpx").ok_or_else(|| {
            CoreError::new(
                "ProviderMissing",
                "httpx is not installed. Install it manually to run HTTP probing.",
            )
        })?;
        // Non-intrusive metadata only; targets passed as an argument list (never a
        // shell). No fuzzing, no path brute force, no active exploitation flags.
        let mut args = vec![
            "-json".into(),
            "-silent".into(),
            "-no-color".into(),
            "-title".into(),
            "-status-code".into(),
            "-tech-detect".into(),
            "-web-server".into(),
            "-content-length".into(),
            "-location".into(),
            "-u".into(),
            urls.join(","),
        ];
        let outcome = process::run(
            &executable,
            &args,
            ctx.cancelled,
            ctx.deadline,
            HTTPX_STDOUT_CAP,
            HTTPX_STDERR_CAP,
        )?;
        if outcome.cancelled {
            return Err(CoreError::new("Cancelled", "HTTP probing cancelled."));
        }
        let mut command = vec![executable.to_string_lossy().into_owned()];
        command.append(&mut args);
        Ok(Execution {
            target: target.into(),
            capability,
            command,
            stdout: outcome.stdout,
            stderr: outcome.stderr,
            exit_status: outcome.exit_status,
            pid: outcome.pid,
            timed_out: outcome.timed_out,
            started_at,
            ended_at: crate::now(),
            artifacts: Vec::new(),
            cancelled: false,
        })
    }

    fn parse(&self, execution: &Execution) -> Result<Vec<Discovery>> {
        let text = String::from_utf8_lossy(&execution.stdout);
        let mut discoveries = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for line in text.lines().take(5000) {
            let line = line.trim();
            if line.is_empty() || line.len() > 8192 {
                continue;
            }
            let Ok(record) = serde_json::from_str::<HttpxRecord>(line) else {
                continue; // skip malformed line, keep the rest
            };
            let Some(raw_url) = record.url.or_else(|| record.input.clone()) else {
                continue;
            };
            let Ok(url) = crate::targets::web_url(&raw_url) else {
                continue;
            };
            if !seen.insert(url.clone()) {
                continue;
            }
            // The website is linked to its owning host IP (a definitely-known
            // asset). Derive the host from the normalized probe URL and strip any
            // IPv6 brackets so it matches the bare IPAddress asset identity for both
            // address families (record.host port/bracket formatting is unreliable).
            let host = url::Url::parse(&url)
                .ok()
                .and_then(|u| u.host_str().map(|h| h.trim_matches(['[', ']']).to_owned()));
            let mut metadata = json!({ "tool": "httpx" });
            if let Some(code) = record.status_code {
                metadata["status_code"] = json!(code);
            }
            if let Some(t) = &record.title {
                metadata["title"] = json!(clip(t, 512));
            }
            if let Some(s) = &record.webserver {
                metadata["server"] = json!(clip(s, 256));
            }
            if let Some(c) = record.content_length {
                metadata["content_length"] = json!(c);
            }
            if let Some(l) = &record.location {
                metadata["location"] = json!(clip(l, 1024));
            }
            discoveries.push(Discovery {
                asset_type: AssetType::Website,
                value: url.clone(),
                source: host,
                relationship: Some(RelationshipType::HasEndpoint),
                observation: None,
                metadata,
            });
            // Technology assets are reusable identities shared across websites.
            for tech in record.tech.iter().take(50) {
                let name = clip(tech.trim(), 128);
                if name.is_empty() {
                    continue;
                }
                discoveries.push(Discovery {
                    asset_type: AssetType::Technology,
                    value: name,
                    source: Some(url.clone()),
                    relationship: Some(RelationshipType::UsesTechnology),
                    observation: None,
                    metadata: json!({ "tool": "httpx" }),
                });
            }
        }
        Ok(discoveries)
    }
}

// ---------------------------------------------------------------------------
// Katana provider (Phase 2A). Performs bounded, same-host web crawling from an
// explicitly selected in-scope HTTP(S) URL. Standard mode only: no headless
// browser, automatic form filling, authentication flows, or out-of-scope crawl.
// ---------------------------------------------------------------------------

pub struct KatanaProvider;

const KATANA_STDOUT_CAP: usize = 512 * 1024;
const KATANA_STDERR_CAP: usize = 64 * 1024;

impl KatanaProvider {
    fn arguments(target: &str) -> Vec<String> {
        vec![
            "-u".into(),
            target.into(),
            "-d".into(),
            "2".into(),
            "-fs".into(),
            "fqdn".into(),
            "-ct".into(),
            "20s".into(),
            "-timeout".into(),
            "5".into(),
            "-retry".into(),
            "0".into(),
            "-mrs".into(),
            "1048576".into(),
            "-j".into(),
            "-silent".into(),
            "-nc".into(),
            "-ob".into(),
            "-or".into(),
            "-iqp".into(),
        ]
    }
}

impl Provider for KatanaProvider {
    fn setup(&self) -> Option<ProviderSetup> {
        Some(ProviderSetup {
            install_command: Some("brew install katana".into()),
            homepage: Some("https://github.com/projectdiscovery/katana".into()),
            documentation: Some("https://docs.projectdiscovery.io/tools/katana/overview".into()),
        })
    }

    fn metadata(&self) -> ProviderMetadata {
        ProviderMetadata {
            id: "katana".into(),
            name: "Katana".into(),
            description:
                "Bounded same-host web crawling via the external ProjectDiscovery Katana tool."
                    .into(),
            version: "external".into(),
            risk_class: RiskClass::ActiveLowImpact,
            network_activity: NetworkActivity::Network,
            capabilities: vec![Capability::WebCrawling],
            supported_target_types: vec![TargetType::URL],
        }
    }

    fn installation(&self, tools: &ToolConfig) -> Installation {
        let Some(executable) = tools.locate("katana") else {
            return Installation::Missing;
        };
        let cancelled = AtomicBool::new(false);
        match process::run(
            &executable,
            &["-version".into()],
            &cancelled,
            Instant::now() + Duration::from_secs(5),
            KATANA_STDERR_CAP,
            KATANA_STDERR_CAP,
        ) {
            Ok(outcome) if outcome.timed_out || outcome.exit_status != Some(0) => {
                Installation::ExecutionError {
                    message: "The provider version probe failed or timed out.".into(),
                }
            }
            Ok(outcome) => {
                let mut text = String::from_utf8_lossy(&outcome.stdout).into_owned();
                text.push('\n');
                text.push_str(&String::from_utf8_lossy(&outcome.stderr));
                let version = process::scan_version(&text).unwrap_or_else(|| "unknown".into());
                Installation::Installed {
                    version,
                    path: Some(executable),
                }
            }
            Err(error) => Installation::ExecutionError {
                message: error.message,
            },
        }
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(30)
    }

    fn execute(
        &self,
        target: &str,
        capability: Capability,
        _inputs: &[Asset],
        ctx: &ProviderContext,
    ) -> Result<Execution> {
        let target = crate::targets::web_url(target)?;
        let executable = ctx.tools.locate("katana").ok_or_else(|| {
            CoreError::new(
                "ProviderMissing",
                "Katana is not installed. Install it manually to run Web Recon.",
            )
        })?;
        let mut args = Self::arguments(&target);
        let outcome = process::run(
            &executable,
            &args,
            ctx.cancelled,
            ctx.deadline,
            KATANA_STDOUT_CAP,
            KATANA_STDERR_CAP,
        )?;
        if outcome.cancelled {
            return Err(CoreError::new("Cancelled", "Web crawling cancelled."));
        }
        let mut command = vec![executable.to_string_lossy().into_owned()];
        command.append(&mut args);
        Ok(Execution {
            target,
            capability,
            command,
            stdout: outcome.stdout,
            stderr: outcome.stderr,
            exit_status: outcome.exit_status,
            pid: outcome.pid,
            timed_out: outcome.timed_out,
            started_at: outcome.started_at,
            ended_at: outcome.ended_at,
            artifacts: Vec::new(),
            cancelled: false,
        })
    }

    fn parse(&self, execution: &Execution) -> Result<Vec<Discovery>> {
        if execution.stdout.len() > KATANA_STDOUT_CAP {
            return Err(CoreError::new(
                "ProviderFailure",
                "Katana output exceeds the size budget.",
            ));
        }
        let target = crate::targets::web_url(&execution.target)?;
        let target_url = url::Url::parse(&target)
            .map_err(|_| CoreError::new("ProviderFailure", "Katana target URL is invalid."))?;
        let target_host = target_url
            .host_str()
            .ok_or_else(|| CoreError::new("ProviderFailure", "Katana target has no host."))?;

        let mut discoveries = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for line in String::from_utf8_lossy(&execution.stdout)
            .lines()
            .take(3000)
        {
            let line = line.trim();
            if line.is_empty() || line.len() > 8192 {
                continue;
            }
            let Ok(record) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let raw_url = record
                .pointer("/request/endpoint")
                .and_then(serde_json::Value::as_str)
                .or_else(|| record.get("url").and_then(serde_json::Value::as_str))
                .or_else(|| record.get("endpoint").and_then(serde_json::Value::as_str));
            let Some(raw_url) = raw_url else {
                continue;
            };
            let Ok(url) = crate::targets::web_url(raw_url) else {
                continue;
            };
            let Ok(parsed) = url::Url::parse(&url) else {
                continue;
            };
            if parsed.host_str() != Some(target_host) || url == target || !seen.insert(url.clone())
            {
                continue;
            }
            let mut metadata = json!({"tool":"katana"});
            if let Some(method) = record
                .pointer("/request/method")
                .and_then(serde_json::Value::as_str)
            {
                metadata["method"] = json!(clip(method, 16));
            }
            if let Some(status) = record
                .pointer("/response/status_code")
                .and_then(serde_json::Value::as_i64)
            {
                metadata["status_code"] = json!(status);
            }
            discoveries.push(Discovery {
                asset_type: AssetType::URL,
                value: url,
                source: Some(target.clone()),
                relationship: Some(RelationshipType::HasEndpoint),
                observation: None,
                metadata,
            });
        }
        Ok(discoveries)
    }
}

/// Truncate untrusted strings to a bounded length (char-safe).
fn clip(value: &str, max: usize) -> String {
    // Drop control characters (defense against ANSI/terminal-escape injection from
    // untrusted provider output) and bound the length (char-safe).
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(max)
        .collect()
}

// ---------------------------------------------------------------------------
// ffuf content-discovery provider (Phase 2C). Bounded path discovery over an
// explicitly selected in-scope HTTP(S) URL with a user-chosen wordlist. ACTIVE;
// only runs from its own Content Discovery chain, never automatically.
// ---------------------------------------------------------------------------

/// Conservative Phase 2C wordlist limits (the Rust core is the security boundary).
pub const WORDLIST_MAX_ENTRIES: usize = 500;
pub const WORDLIST_MAX_BYTES: u64 = 1024 * 1024;
pub const WORDLIST_MAX_LINE_BYTES: usize = 512;

/// Validate a user-selected wordlist and return its usable entry count. Blank lines
/// and `#` comments are ignored; the file must be UTF-8 text within the limits. This
/// is enforced in the core (never trusting Swift-provided metadata) and fails clearly
/// rather than silently truncating.
pub fn validate_wordlist(path: &std::path::Path) -> Result<usize> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| CoreError::new("WordlistMissing", "The selected wordlist does not exist."))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CoreError::new(
            "WordlistMissing",
            "The wordlist must be a regular file (symlinks are not accepted).",
        ));
    }
    if metadata.len() > WORDLIST_MAX_BYTES {
        return Err(CoreError::new(
            "WordlistTooLarge",
            "The wordlist exceeds the 1 MiB limit.",
        ));
    }
    let data = std::fs::read(path)
        .map_err(|_| CoreError::new("WordlistMissing", "The wordlist could not be read."))?;
    if data.contains(&0) {
        return Err(CoreError::new(
            "InvalidData",
            "The wordlist appears to be binary (contains NUL bytes).",
        ));
    }
    let text = std::str::from_utf8(&data)
        .map_err(|_| CoreError::new("InvalidData", "The wordlist must be UTF-8 text."))?;
    let mut count = 0usize;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue; // blank lines and # comments are ignored
        }
        if line.len() > WORDLIST_MAX_LINE_BYTES {
            return Err(CoreError::new(
                "WordlistTooLarge",
                "A wordlist entry exceeds the 512-byte line limit.",
            ));
        }
        count += 1;
        if count > WORDLIST_MAX_ENTRIES {
            return Err(CoreError::new(
                "WordlistTooLarge",
                "The wordlist exceeds the 500-entry limit for Phase 2C.",
            ));
        }
    }
    if count == 0 {
        return Err(CoreError::new(
            "WordlistMissing",
            "The wordlist has no usable entries.",
        ));
    }
    Ok(count)
}

pub struct FfufProvider;

const FFUF_STDOUT_CAP: usize = 512 * 1024;
const FFUF_STDERR_CAP: usize = 64 * 1024;

#[derive(Deserialize)]
struct FfufOutput {
    #[serde(default)]
    results: Vec<FfufResult>,
}
#[derive(Deserialize)]
struct FfufResult {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    status: Option<i64>,
    #[serde(default)]
    length: Option<i64>,
    #[serde(default)]
    redirectlocation: Option<String>,
}

impl FfufProvider {
    /// Append the FUZZ keyword at a path boundary of the normalized URL.
    fn fuzz_url(url: &str) -> String {
        if url.ends_with('/') {
            format!("{url}FUZZ")
        } else {
            format!("{url}/FUZZ")
        }
    }

    /// Deterministic, bounded argument array. No shell, no recursion, redirects off.
    fn arguments(fuzz_url: &str, wordlist: &str) -> Vec<String> {
        vec![
            "-u".into(),
            fuzz_url.into(),
            "-w".into(),
            wordlist.into(),
            "-mc".into(),
            // Useful statuses; 404 is intentionally excluded so it creates no asset.
            "200,204,301,302,307,308,401,403,405".into(),
            "-t".into(),
            "10".into(), // bounded concurrency
            "-rate".into(),
            "10".into(), // bounded requests/sec
            "-timeout".into(),
            "5".into(),     // per-request seconds
            "-json".into(), // machine-readable output to stdout
        ]
    }
}

impl Provider for FfufProvider {
    fn setup(&self) -> Option<ProviderSetup> {
        Some(ProviderSetup {
            install_command: Some("brew install ffuf".into()),
            homepage: Some("https://github.com/ffuf/ffuf".into()),
            documentation: Some("https://github.com/ffuf/ffuf#usage".into()),
        })
    }

    fn metadata(&self) -> ProviderMetadata {
        ProviderMetadata {
            id: "ffuf".into(),
            name: "ffuf".into(),
            description:
                "Bounded path/content discovery over an in-scope HTTP(S) URL with a chosen wordlist."
                    .into(),
            version: "external".into(),
            risk_class: RiskClass::Active,
            network_activity: NetworkActivity::Network,
            capabilities: vec![Capability::ContentDiscovery],
            supported_target_types: vec![TargetType::URL],
        }
    }

    fn installation(&self, tools: &ToolConfig) -> Installation {
        let Some(executable) = tools.locate("ffuf") else {
            return Installation::Missing;
        };
        let cancelled = AtomicBool::new(false);
        match process::run(
            &executable,
            &["-V".into()],
            &cancelled,
            Instant::now() + Duration::from_secs(5),
            FFUF_STDERR_CAP,
            FFUF_STDERR_CAP,
        ) {
            Ok(outcome) if outcome.timed_out || outcome.exit_status != Some(0) => {
                Installation::ExecutionError {
                    message: "The provider version probe failed or timed out.".into(),
                }
            }
            Ok(outcome) => {
                let mut text = String::from_utf8_lossy(&outcome.stdout).into_owned();
                text.push('\n');
                text.push_str(&String::from_utf8_lossy(&outcome.stderr));
                let version = process::scan_version(&text).unwrap_or_else(|| "unknown".into());
                Installation::Installed {
                    version,
                    path: Some(executable),
                }
            }
            Err(error) => Installation::ExecutionError {
                message: error.message,
            },
        }
    }

    fn timeout(&self) -> Duration {
        Duration::from_secs(90)
    }

    fn execute(
        &self,
        target: &str,
        capability: Capability,
        _inputs: &[Asset],
        ctx: &ProviderContext,
    ) -> Result<Execution> {
        let started_at = crate::now();
        let base = crate::targets::web_url(target)?;
        let wordlist = ctx
            .options
            .get("wordlist_path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                CoreError::new(
                    "WordlistMissing",
                    "No wordlist was provided for content discovery.",
                )
            })?;
        // Re-validate in the provider — the core is the security boundary.
        validate_wordlist(std::path::Path::new(wordlist))?;

        let executable = ctx.tools.locate("ffuf").ok_or_else(|| {
            CoreError::new(
                "ProviderMissing",
                "ffuf is not installed. Install it manually to run content discovery.",
            )
        })?;
        let fuzz_url = Self::fuzz_url(&base);
        let args = Self::arguments(&fuzz_url, wordlist);
        let outcome = process::run(
            &executable,
            &args,
            ctx.cancelled,
            ctx.deadline,
            FFUF_STDOUT_CAP,
            FFUF_STDERR_CAP,
        )?;
        if outcome.cancelled {
            return Err(CoreError::new("Cancelled", "Content discovery cancelled."));
        }
        // Persisted command redacts the local wordlist path to its file name only,
        // preserving provenance without leaking a private filesystem path. The URL
        // target and provider identity are kept.
        let redacted_wordlist = std::path::Path::new(wordlist)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "<wordlist>".into());
        let mut command = vec![executable.to_string_lossy().into_owned()];
        command.extend(Self::arguments(&fuzz_url, &redacted_wordlist));
        Ok(Execution {
            target: target.into(),
            capability,
            command,
            stdout: outcome.stdout,
            stderr: outcome.stderr,
            exit_status: outcome.exit_status,
            pid: outcome.pid,
            timed_out: outcome.timed_out,
            started_at,
            ended_at: crate::now(),
            artifacts: Vec::new(),
            cancelled: false,
        })
    }

    fn parse(&self, execution: &Execution) -> Result<Vec<Discovery>> {
        let base = crate::targets::web_url(&execution.target)?;
        let base_host = url::Url::parse(&base)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned));
        let output: FfufOutput = serde_json::from_slice(&execution.stdout)
            .map_err(|_| CoreError::new("ProviderFailure", "ffuf output is malformed."))?;
        let mut discoveries = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for result in output.results.into_iter().take(5000) {
            let Some(raw_url) = result.url else { continue };
            if raw_url.len() > 2048 {
                continue;
            }
            // 404 creates no asset (defensive; -mc already excludes it).
            if result.status == Some(404) {
                continue;
            }
            let Ok(url) = crate::targets::web_url(&raw_url) else {
                continue; // malformed/credential URL
            };
            // Same-host only: never turn one authorized site into permission to
            // record another host's paths.
            let host = url::Url::parse(&url)
                .ok()
                .and_then(|u| u.host_str().map(str::to_owned));
            if host.is_none() || host != base_host {
                continue;
            }
            if !seen.insert(url.clone()) {
                continue;
            }
            let mut metadata = json!({"tool": "ffuf"});
            if let Some(status) = result.status {
                metadata["status"] = json!(status);
            }
            if let Some(length) = result.length {
                metadata["content_length"] = json!(length);
            }
            if let Some(redirect) = result.redirectlocation.filter(|r| !r.is_empty()) {
                metadata["redirect_location"] = json!(clip(&redirect, 1024));
            }
            discoveries.push(Discovery {
                asset_type: AssetType::URL,
                value: url,
                source: Some(base.clone()),
                relationship: Some(RelationshipType::HasEndpoint),
                observation: None,
                metadata,
            });
        }
        Ok(discoveries)
    }
}

// ---------------------------------------------------------------------------
// Native HTTP analysis provider (Phase 2B). Built-in (no external tool). Takes an
// explicitly selected in-scope HTTP(S) URL and produces normalized web-security
// metadata: response info, security headers, cookie flags (never values), CORS
// headers, a scope-checked redirect chain, and conservative robots.txt parsing.
// ACTIVE_LOW_IMPACT: ordinary HTTP requests to an authorized target only.
// ---------------------------------------------------------------------------

pub struct NativeHttpProvider {
    transport: Arc<dyn WebTransport>,
}

impl NativeHttpProvider {
    pub fn new(transport: Arc<dyn WebTransport>) -> Self {
        Self { transport }
    }
}

const MAX_REDIRECTS: usize = 5;
/// Security response headers MACSPLOIT normalizes (collection only; absence is not
/// treated as a finding in this phase).
const SECURITY_HEADERS: &[&str] = &[
    "strict-transport-security",
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
];
const CORS_HEADERS: &[&str] = &[
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
];

/// A validated http(s) URL with no embedded credentials.
fn safe_http_url(value: &str) -> Option<url::Url> {
    let parsed = url::Url::parse(value).ok()?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return None;
    }
    Some(parsed)
}

/// Parse one Set-Cookie header into security metadata, discarding the value.
fn cookie_metadata(set_cookie: &str) -> serde_json::Value {
    let mut parts = set_cookie.split(';');
    let name = parts
        .next()
        .and_then(|p| p.split('=').next())
        .unwrap_or("")
        .trim();
    let mut secure = false;
    let mut http_only = false;
    let mut same_site: Option<String> = None;
    let mut path: Option<String> = None;
    for attr in parts {
        let attr = attr.trim();
        let (key, val) = attr.split_once('=').unwrap_or((attr, ""));
        match key.to_ascii_lowercase().as_str() {
            "secure" => secure = true,
            "httponly" => http_only = true,
            "samesite" => same_site = Some(clip(val.trim(), 16)),
            "path" => path = Some(clip(val.trim(), 128)),
            _ => {}
        }
    }
    json!({
        "name": clip(name, 128),
        "secure": secure,
        "http_only": http_only,
        "same_site": same_site,
        "path": path,
    })
}

/// Conservative robots.txt parsing: bounded counts and line lengths.
fn parse_robots(body: &[u8]) -> serde_json::Value {
    let text = String::from_utf8_lossy(body);
    let mut user_agents = Vec::new();
    let mut disallow = Vec::new();
    let mut allow = Vec::new();
    let mut sitemaps = Vec::new();
    for line in text.lines().take(2000) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.len() > 2048 {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = clip(value.trim(), 1024);
        match key.trim().to_ascii_lowercase().as_str() {
            "user-agent" if user_agents.len() < 100 => user_agents.push(value),
            "disallow" if disallow.len() < 500 => disallow.push(value),
            "allow" if allow.len() < 500 => allow.push(value),
            "sitemap" if sitemaps.len() < 100 => sitemaps.push(value),
            _ => {}
        }
    }
    json!({"user_agents": user_agents, "disallow": disallow, "allow": allow, "sitemaps": sitemaps})
}

impl Provider for NativeHttpProvider {
    fn metadata(&self) -> ProviderMetadata {
        ProviderMetadata {
            id: "native_http".into(),
            name: "Native HTTP Analysis".into(),
            description:
                "Built-in HTTP(S) analysis: response, security headers, cookie flags, CORS, redirects, robots."
                    .into(),
            version: "built-in".into(),
            risk_class: RiskClass::ActiveLowImpact,
            network_activity: NetworkActivity::Network,
            capabilities: vec![Capability::WebAnalysis],
            supported_target_types: vec![TargetType::URL],
        }
    }

    fn installation(&self, _tools: &ToolConfig) -> Installation {
        Installation::BuiltIn
    }

    fn execute(
        &self,
        target: &str,
        capability: Capability,
        _inputs: &[Asset],
        ctx: &ProviderContext,
    ) -> Result<Execution> {
        let started_at = crate::now();
        let mut notes: Vec<String> = Vec::new();
        let mut redirects: Vec<serde_json::Value> = Vec::new();

        let Some(start) = safe_http_url(target) else {
            return Err(CoreError::new(
                "InvalidTarget",
                "Native HTTP analysis requires an http(s) URL without credentials.",
            ));
        };
        let robots_host_url = format!(
            "{}://{}{}/robots.txt",
            start.scheme(),
            start.host_str().unwrap_or(""),
            start.port().map(|p| format!(":{p}")).unwrap_or_default()
        );

        // Follow redirects manually so every hop is scope-checked.
        let mut current = target.to_owned();
        let mut final_response: Option<WebResponse> = None;
        let mut final_url = current.clone();
        for hop in 0..=MAX_REDIRECTS {
            if ctx.cancelled.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(CoreError::new("Cancelled", "Web analysis cancelled."));
            }
            let response = self
                .transport
                .fetch(&current, ctx.deadline, ctx.cancelled)?;
            let status = response.status;
            if (300..400).contains(&status) {
                let location = response.header("location").map(str::to_owned);
                let next = location.as_ref().and_then(|loc| {
                    url::Url::parse(&current)
                        .ok()?
                        .join(loc)
                        .ok()
                        .map(String::from)
                });
                let follow = match &next {
                    Some(next_url) if hop < MAX_REDIRECTS => {
                        if safe_http_url(next_url).is_none() {
                            notes
                                .push("redirect to unsupported/credential URL not followed".into());
                            false
                        } else if !crate::scope::contains(ctx.scope, next_url) {
                            notes.push("redirect to out-of-scope host not followed".into());
                            false
                        } else {
                            true
                        }
                    }
                    Some(_) => {
                        notes.push("redirect limit reached".into());
                        false
                    }
                    None => false,
                };
                redirects.push(json!({
                    "url": clip(&current, 2048),
                    "status": status,
                    "location": next.as_deref().map(|n| clip(n, 2048)),
                    "followed": follow,
                }));
                if follow {
                    current = next.expect("followed redirect has a destination");
                    final_url = current.clone();
                    continue;
                }
                final_url = current.clone();
                final_response = Some(response);
                break;
            }
            final_url = current.clone();
            final_response = Some(response);
            break;
        }

        let response = final_response.unwrap_or_default();

        // Security headers (present only).
        let mut security_headers = serde_json::Map::new();
        for name in SECURITY_HEADERS {
            if let Some(value) = response.header(name) {
                security_headers.insert((*name).to_owned(), json!(clip(value, 4096)));
            }
        }
        // CORS headers (present only).
        let mut cors = serde_json::Map::new();
        for name in CORS_HEADERS {
            if let Some(value) = response.header(name) {
                cors.insert((*name).to_owned(), json!(clip(value, 2048)));
            }
        }
        // Cookie flags only — values are never recorded.
        let cookies: Vec<serde_json::Value> = response
            .header_all("set-cookie")
            .iter()
            .take(100)
            .map(|c| cookie_metadata(c))
            .collect();

        // robots.txt for the selected host (in scope, authorized).
        let robots = match self
            .transport
            .fetch(&robots_host_url, ctx.deadline, ctx.cancelled)
        {
            Ok(r) if r.status == 200 => {
                json!({"retrieved": true, "status": 200, "records": parse_robots(&r.body)})
            }
            Ok(r) => json!({"retrieved": false, "status": r.status}),
            Err(error) if error.code == "Cancelled" => {
                return Err(error);
            }
            Err(error) => json!({"retrieved": false, "error": error.code}),
        };

        let report = json!({
            "provider": "native_http",
            "target": target,
            "final_url": final_url,
            "status": response.status,
            "content_type": response.header("content-type").map(|v| clip(v, 256)),
            "content_length": response.header("content-length").map(|v| clip(v, 32)),
            "server": response.header("server").map(|v| clip(v, 256)),
            "redirects": redirects,
            "security_headers": security_headers,
            "cors": cors,
            "cookies": cookies,
            "robots": robots,
            "notes": notes,
        });
        let stdout = serde_json::to_vec_pretty(&report)?;
        Ok(Execution {
            target: target.into(),
            capability,
            command: vec!["native_http".into(), target.into()],
            stdout,
            stderr: Vec::new(),
            exit_status: Some(0),
            pid: None,
            timed_out: false,
            started_at,
            ended_at: crate::now(),
            artifacts: Vec::new(),
            cancelled: false,
        })
    }

    fn parse(&self, execution: &Execution) -> Result<Vec<Discovery>> {
        let report: serde_json::Value = serde_json::from_slice(&execution.stdout)
            .map_err(|_| CoreError::new("ProviderFailure", "Native HTTP output is malformed."))?;
        let final_url = report
            .get("final_url")
            .and_then(|v| v.as_str())
            .filter(|s| safe_http_url(s).is_some())
            .map(str::to_owned)
            .unwrap_or_else(|| execution.target.clone());
        // Enrich the Website asset for this URL with a concise, non-sensitive
        // summary; the full normalized detail lives in the evidence envelope.
        let present: Vec<&str> = SECURITY_HEADERS
            .iter()
            .filter(|h| report["security_headers"].get(**h).is_some())
            .copied()
            .collect();
        let metadata = json!({
            "tool": "native_http",
            "status": report.get("status"),
            "server": report.get("server"),
            "security_headers_present": present,
            "cookie_count": report["cookies"].as_array().map(|a| a.len()).unwrap_or(0),
            "cors_present": report["cors"].as_object().map(|o| !o.is_empty()).unwrap_or(false),
            "redirect_count": report["redirects"].as_array().map(|a| a.len()).unwrap_or(0),
            "robots_retrieved": report["robots"].get("retrieved") == Some(&json!(true)),
        });
        Ok(vec![Discovery {
            asset_type: AssetType::Website,
            value: final_url,
            source: None,
            relationship: None,
            observation: None,
            metadata,
        }])
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
            scope: &[],
            options: &serde_json::Value::Null,
        }
    }

    fn context_scoped<'a>(
        tools: &'a ToolConfig,
        cancelled: &'a AtomicBool,
        scope: &'a [String],
    ) -> ProviderContext<'a> {
        ProviderContext {
            cancelled,
            deadline: Instant::now() + Duration::from_secs(10),
            tools,
            scope,
            options: &serde_json::Value::Null,
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
            artifacts: Vec::new(),
            cancelled: false,
        }
    }

    #[test]
    fn synthetic_provider_is_passive_and_selected_by_capability() {
        let provider = ProviderRegistry::default()
            .named("synthetic", Capability::SubdomainDiscovery)
            .unwrap();
        assert_eq!(provider.metadata().risk_class, RiskClass::Passive);
        assert_eq!(provider.metadata().id, "synthetic");
        assert_eq!(provider.metadata().network_activity, NetworkActivity::None);
    }

    #[test]
    fn provider_network_activity_is_independent_of_execution_kind() {
        let metadata = ProviderRegistry::default().metadata();
        let activity = |id: &str| {
            metadata
                .iter()
                .find(|provider| provider.id == id)
                .unwrap()
                .network_activity
        };
        assert_eq!(activity("synthetic"), NetworkActivity::None);
        assert_eq!(activity("native_dns"), NetworkActivity::Network);
        assert_eq!(activity("native_http"), NetworkActivity::Network);
        for id in ["subfinder", "nmap", "httpx", "katana", "ffuf"] {
            assert_eq!(activity(id), NetworkActivity::Network);
        }
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
        assert_eq!(metadata.network_activity, NetworkActivity::Network);
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
        assert_eq!(
            SubfinderProvider.installation(&missing),
            Installation::Missing
        );
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
            "{\"host\":\"API.EXAMPLE.TEST.\"}\n", // dup after normalization
            "{\"host\":\"dev.example.test\",\"source\":\"crtsh\"}\n",
            "dev.example.test\n",                // dup bare line
            "{\"host\":\"example.test\"}\n",     // apex, skipped
            "not-json-and-not-a-host !!\n",      // malformed, skipped
            "{\"host\":\"third-party.test\"}\n", // unrelated, preserved w/o rel
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
        assert_eq!(
            discoveries[0].relationship,
            Some(RelationshipType::HasSubdomain)
        );
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
            .execute(
                "example.test",
                Capability::DnsResolution,
                &inputs,
                &context(&tools, &cancelled),
            )
            .unwrap();
        let discoveries = provider.parse(&execution).unwrap();
        // api -> 192.0.2.10 (deduped) + 2001:db8::10 ; dev -> 192.0.2.11  => 3
        assert_eq!(discoveries.len(), 3);
        assert!(discoveries
            .iter()
            .all(|d| d.asset_type == AssetType::IPAddress
                && d.relationship == Some(RelationshipType::ResolvesTo)));
        assert_eq!(
            discoveries
                .iter()
                .filter(|d| d.source.as_deref() == Some("api.example.test"))
                .count(),
            2
        );
    }

    #[test]
    fn native_dns_no_records_yields_no_discoveries() {
        use crate::dns::{DnsOutcome, StaticDnsResolver};
        let resolver =
            StaticDnsResolver::new().with_outcome("api.example.test", DnsOutcome::NoRecords);
        let provider = NativeDnsProvider::new(Arc::new(resolver));
        let tools = ToolConfig::default();
        let cancelled = AtomicBool::new(false);
        let inputs = vec![dns_asset(AssetType::Subdomain, "api.example.test")];
        let execution = provider
            .execute(
                "example.test",
                Capability::DnsResolution,
                &inputs,
                &context(&tools, &cancelled),
            )
            .unwrap();
        assert!(provider.parse(&execution).unwrap().is_empty());
    }

    #[test]
    fn native_dns_falls_back_to_target_when_no_host_inputs() {
        use crate::dns::StaticDnsResolver;
        let resolver =
            StaticDnsResolver::new().with("example.test", &["192.0.2.1".parse().unwrap()], &[]);
        let provider = NativeDnsProvider::new(Arc::new(resolver));
        let tools = ToolConfig::default();
        let cancelled = AtomicBool::new(false);
        let execution = provider
            .execute(
                "example.test",
                Capability::DnsResolution,
                &[],
                &context(&tools, &cancelled),
            )
            .unwrap();
        let discoveries = provider.parse(&execution).unwrap();
        assert_eq!(discoveries.len(), 1);
        assert_eq!(discoveries[0].value, "192.0.2.1");
        assert_eq!(discoveries[0].source.as_deref(), Some("example.test"));
    }

    #[test]
    fn native_dns_cancellation_is_reported() {
        use crate::dns::StaticDnsResolver;
        let resolver = StaticDnsResolver::new().with(
            "api.example.test",
            &["192.0.2.10".parse().unwrap()],
            &[],
        );
        let provider = NativeDnsProvider::new(Arc::new(resolver));
        let tools = ToolConfig::default();
        let cancelled = AtomicBool::new(true);
        let inputs = vec![dns_asset(AssetType::Subdomain, "api.example.test")];
        let error = provider
            .execute(
                "example.test",
                Capability::DnsResolution,
                &inputs,
                &context(&tools, &cancelled),
            )
            .unwrap_err();
        assert_eq!(error.code, "Cancelled");
    }

    // --- Nmap provider ---

    fn nmap_exec(xml: &str) -> Execution {
        Execution {
            target: "192.0.2.10".into(),
            capability: Capability::PortDiscovery,
            command: vec!["nmap".into()],
            stdout: xml.as_bytes().to_vec(),
            stderr: Vec::new(),
            exit_status: Some(0),
            pid: None,
            timed_out: false,
            started_at: crate::now(),
            ended_at: crate::now(),
            artifacts: Vec::new(),
            cancelled: false,
        }
    }

    #[test]
    fn nmap_metadata_is_active_ports_services() {
        let metadata = NmapProvider.metadata();
        assert_eq!(metadata.id, "nmap");
        assert_eq!(metadata.risk_class, RiskClass::Active);
        assert_eq!(metadata.network_activity, NetworkActivity::Network);
        assert_eq!(
            metadata.capabilities,
            vec![Capability::PortDiscovery, Capability::ServiceFingerprinting]
        );
        assert_eq!(metadata.supported_target_types, vec![TargetType::IPAddress]);
        assert_eq!(NmapProvider.timeout(), Duration::from_secs(120));
    }

    #[test]
    fn nmap_arguments_are_unprivileged_and_family_aware() {
        let v4 = NmapProvider::arguments(false, &["192.0.2.10".into()]);
        assert!(v4.contains(&"-sT".to_string())); // connect scan, no root
        assert!(v4.contains(&"-sV".to_string()));
        assert!(v4.windows(2).any(|w| w == ["--top-ports", "100"]));
        assert!(v4.windows(2).any(|w| w == ["-oX", "-"]));
        assert!(!v4.contains(&"-6".to_string()));
        // No aggressive/root/NSE/UDP/evasion/timing flags creep in for any chain.
        assert!(!v4.iter().any(|a| matches!(
            a.as_str(),
            "-A" | "-O" | "--script" | "-sS" | "-sU" | "-Pn" | "-T5" | "-T4" | "-D" | "-f" | "-S"
        )));
        assert_eq!(v4.last().unwrap(), "192.0.2.10");
        let v6 = NmapProvider::arguments(true, &["2001:db8::1".into()]);
        assert!(v6.contains(&"-6".to_string()));
        assert_eq!(v6.last().unwrap(), "2001:db8::1");
    }

    #[test]
    fn nmap_parses_ports_and_services_with_relationships() {
        let xml = r#"<?xml version="1.0"?><nmaprun><host><status state="up"/>
            <address addr="192.0.2.10" addrtype="ipv4"/><ports>
            <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6"/></port>
            <port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" tunnel="ssl"/></port>
            </ports></host></nmaprun>"#;
        let discoveries = NmapProvider.parse(&nmap_exec(xml)).unwrap();
        assert_eq!(discoveries.len(), 4); // 2 ports + 2 services
        let port = &discoveries[0];
        assert_eq!(port.asset_type, AssetType::Port);
        assert_eq!(port.value, "192.0.2.10/tcp/22");
        assert_eq!(port.relationship, Some(RelationshipType::Exposes));
        assert_eq!(port.source.as_deref(), Some("192.0.2.10"));
        let service = &discoveries[1];
        assert_eq!(service.asset_type, AssetType::Service);
        assert_eq!(service.value, "192.0.2.10/tcp/22/ssh");
        assert_eq!(service.relationship, Some(RelationshipType::Serves));
        assert_eq!(service.source.as_deref(), Some("192.0.2.10/tcp/22"));
        assert_eq!(service.metadata["product"], json!("OpenSSH"));
    }

    #[test]
    fn nmap_parses_real_world_xml_with_doctype_and_stylesheet() {
        // Real nmap output includes an XML declaration, a DOCTYPE, an XSL stylesheet
        // processing instruction, and comments. The parser must handle all of these.
        let xml = concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<!DOCTYPE nmaprun>\n",
            "<?xml-stylesheet href=\"file:///opt/homebrew/share/nmap/nmap.xsl\" type=\"text/xsl\"?>\n",
            "<!-- Nmap scan -->\n",
            "<nmaprun scanner=\"nmap\" version=\"7.991\">",
            "<host><status state=\"up\"/><address addr=\"127.0.0.1\" addrtype=\"ipv4\"/>",
            "<ports><port protocol=\"tcp\" portid=\"443\"><state state=\"open\"/>",
            "<service name=\"https\" product=\"nginx\" tunnel=\"ssl\"/></port></ports></host></nmaprun>",
        );
        let discoveries = NmapProvider.parse(&nmap_exec(xml)).unwrap();
        assert!(discoveries
            .iter()
            .any(|d| d.asset_type == AssetType::Port && d.value == "127.0.0.1/tcp/443"));
        assert!(discoveries
            .iter()
            .any(|d| d.asset_type == AssetType::Service && d.value == "127.0.0.1/tcp/443/https"));
    }

    #[test]
    fn nmap_distinguishes_tcp_udp_and_unknown_service() {
        let xml = r#"<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports>
            <port protocol="tcp" portid="53"><state state="open"/><service name="domain"/></port>
            <port protocol="udp" portid="53"><state state="open"/></port>
            </ports></host></nmaprun>"#;
        let discoveries = NmapProvider.parse(&nmap_exec(xml)).unwrap();
        let ports: Vec<_> = discoveries
            .iter()
            .filter(|d| d.asset_type == AssetType::Port)
            .map(|d| d.value.as_str())
            .collect();
        assert!(ports.contains(&"192.0.2.10/tcp/53"));
        assert!(ports.contains(&"192.0.2.10/udp/53")); // not collapsed with tcp
                                                       // The tcp/53 service has a name; udp/53 had no <service> element.
        assert!(discoveries
            .iter()
            .any(|d| d.value == "192.0.2.10/tcp/53/domain"));
    }

    #[test]
    fn nmap_ipv6_address_is_used_in_identity() {
        let xml = r#"<nmaprun><host><status state="up"/><address addr="2001:db8::10" addrtype="ipv6"/><ports>
            <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
            </ports></host></nmaprun>"#;
        let discoveries = NmapProvider.parse(&nmap_exec(xml)).unwrap();
        assert_eq!(discoveries[0].value, "2001:db8::10/tcp/443");
    }

    #[test]
    fn nmap_skips_closed_ports_and_down_hosts() {
        let xml = r#"<nmaprun>
            <host><status state="down"/><address addr="192.0.2.9" addrtype="ipv4"/></host>
            <host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports>
            <port protocol="tcp" portid="80"><state state="closed"/></port>
            <port protocol="tcp" portid="25"><state state="filtered"/></port>
            </ports></host></nmaprun>"#;
        let discoveries = NmapProvider.parse(&nmap_exec(xml)).unwrap();
        assert!(discoveries.is_empty());
    }

    #[test]
    fn nmap_malformed_xml_is_an_error() {
        assert!(NmapProvider
            .parse(&nmap_exec("<nmaprun><host>oops"))
            .is_err());
    }

    #[test]
    fn nmap_missing_executable_reports_missing() {
        let mut tools = ToolConfig::default();
        tools
            .overrides
            .insert("nmap".into(), "/nonexistent/nmap".into());
        assert_eq!(NmapProvider.installation(&tools), Installation::Missing);
    }

    #[test]
    fn nmap_execute_without_in_scope_ips_is_a_clean_empty_run() {
        let tools = ToolConfig::default();
        let cancelled = AtomicBool::new(false);
        let execution = NmapProvider
            .execute(
                "192.0.2.10",
                Capability::PortDiscovery,
                &[],
                &context(&tools, &cancelled),
            )
            .unwrap();
        assert_eq!(execution.exit_status, Some(0));
        assert!(NmapProvider.parse(&execution).unwrap().is_empty());
    }

    // --- HTTPX provider ---

    fn httpx_exec(jsonl: &str) -> Execution {
        Execution {
            target: "example.test".into(),
            capability: Capability::HttpProbing,
            command: vec!["httpx".into()],
            stdout: jsonl.as_bytes().to_vec(),
            stderr: Vec::new(),
            exit_status: Some(0),
            pid: None,
            timed_out: false,
            started_at: crate::now(),
            ended_at: crate::now(),
            artifacts: Vec::new(),
            cancelled: false,
        }
    }

    #[test]
    fn httpx_metadata_is_low_impact_http_probing() {
        let metadata = HttpxProvider.metadata();
        assert_eq!(metadata.id, "httpx");
        assert_eq!(metadata.risk_class, RiskClass::ActiveLowImpact);
        assert_eq!(metadata.capabilities, vec![Capability::HttpProbing]);
        assert_eq!(HttpxProvider.timeout(), Duration::from_secs(60));
    }

    #[test]
    fn httpx_builds_urls_only_from_web_services() {
        let inputs = vec![
            dns_asset(AssetType::Service, "192.0.2.10/tcp/443/https"),
            dns_asset(AssetType::Service, "192.0.2.10/tcp/80/http"),
            dns_asset(AssetType::Service, "192.0.2.10/tcp/22/ssh"), // not web
            dns_asset(AssetType::IPAddress, "192.0.2.10"),          // not a service
        ];
        let urls = HttpxProvider::urls_from_services(&inputs);
        assert_eq!(urls, vec!["https://192.0.2.10:443", "http://192.0.2.10:80"]);
    }

    #[test]
    fn httpx_brackets_ipv6_service_hosts_and_leaves_ipv4_and_hostnames() {
        // IPv6 literals must be bracketed to form valid URL authorities; IPv4 and
        // already-bracketed/hostname inputs are unchanged (no double-bracketing).
        assert_eq!(HttpxProvider::url_host("192.0.2.10"), "192.0.2.10");
        assert_eq!(HttpxProvider::url_host("example.test"), "example.test");
        assert_eq!(HttpxProvider::url_host("::1"), "[::1]");
        assert_eq!(HttpxProvider::url_host("2001:db8::10"), "[2001:db8::10]");
        assert_eq!(HttpxProvider::url_host("[2001:db8::10]"), "[2001:db8::10]");

        // Service canonical identity host is the bare IP from Nmap; IPv6 Service
        // identities use `/` as the field separator, never the colons in the address.
        let inputs = vec![
            dns_asset(AssetType::Service, "::1/tcp/8080/http"),
            dns_asset(AssetType::Service, "2001:db8::10/tcp/443/https"),
            dns_asset(AssetType::Service, "192.0.2.10/tcp/8080/http"),
        ];
        assert_eq!(
            HttpxProvider::urls_from_services(&inputs),
            vec![
                "http://[::1]:8080",
                "https://[2001:db8::10]:443",
                "http://192.0.2.10:8080",
            ]
        );
    }

    #[test]
    fn httpx_parses_websites_and_technology() {
        let jsonl = concat!(
            r#"{"url":"https://192.0.2.10:443","status_code":200,"title":"Demo","webserver":"nginx","host":"192.0.2.10","tech":["nginx","React"]}"#,
            "\n",
            r#"{"url":"https://192.0.2.10:443","status_code":200,"host":"192.0.2.10"}"#,
            "\n", // duplicate URL
            "not json\n",
        );
        let discoveries = HttpxProvider.parse(&httpx_exec(jsonl)).unwrap();
        // 1 website + 2 technologies (dup url skipped, malformed skipped).
        // web_url normalizes the default 443 port away and adds a trailing slash.
        let canonical = "https://192.0.2.10/";
        let website = discoveries
            .iter()
            .find(|d| d.asset_type == AssetType::Website)
            .unwrap();
        assert_eq!(website.value, canonical);
        assert_eq!(website.relationship, Some(RelationshipType::HasEndpoint));
        assert_eq!(website.source.as_deref(), Some("192.0.2.10"));
        assert_eq!(website.metadata["status_code"], json!(200));
        assert_eq!(website.metadata["server"], json!("nginx"));
        let techs: Vec<_> = discoveries
            .iter()
            .filter(|d| d.asset_type == AssetType::Technology)
            .map(|d| d.value.as_str())
            .collect();
        assert_eq!(techs, vec!["nginx", "React"]);
        assert!(discoveries
            .iter()
            .filter(|d| d.asset_type == AssetType::Technology)
            .all(|d| d.relationship == Some(RelationshipType::UsesTechnology)
                && d.source.as_deref() == Some(canonical)));
    }

    #[test]
    fn httpx_strips_control_sequences_from_untrusted_metadata() {
        let jsonl = "{\"url\":\"https://192.0.2.10:443\",\"title\":\"A\\u001b[31mBAD\\u0007\",\"host\":\"192.0.2.10\"}\n";
        let discoveries = HttpxProvider.parse(&httpx_exec(jsonl)).unwrap();
        let website = discoveries
            .iter()
            .find(|d| d.asset_type == AssetType::Website)
            .unwrap();
        let title = website.metadata["title"].as_str().unwrap();
        assert!(
            !title.chars().any(|c| c.is_control()),
            "control chars leaked: {title:?}"
        );
        assert!(title.contains("BAD"));
    }

    #[test]
    fn nmap_xml_parser_does_not_expand_entities() {
        // Only a *simple* DOCTYPE (no internal subset) is stripped. A DOCTYPE that
        // carries an internal subset — the entity-definition / billion-laughs vector —
        // is left intact, and the DTD-rejecting parser then refuses the document, so a
        // custom entity like &x; is never expanded. The guarantee is deterministic:
        // such input fails to parse.
        let xml = concat!(
            "<?xml version=\"1.0\"?>",
            "<!DOCTYPE nmaprun [ <!ENTITY x \"aaaaaaaaaa\"> ]>",
            "<nmaprun><host><status state=\"up\"/><address addr=\"192.0.2.10\" addrtype=\"ipv4\"/>",
            "<ports><port protocol=\"tcp\" portid=\"80\"><state state=\"open\"/>",
            "<service name=\"&x;\"/></port></ports></host></nmaprun>",
        );
        let result = NmapProvider.parse(&nmap_exec(xml));
        assert!(
            result.is_err(),
            "internal-subset DTD must be rejected, not expanded"
        );
    }

    #[test]
    fn httpx_missing_executable_reports_missing() {
        let mut tools = ToolConfig::default();
        tools
            .overrides
            .insert("httpx".into(), "/nonexistent/httpx".into());
        assert_eq!(HttpxProvider.installation(&tools), Installation::Missing);
    }

    #[test]
    fn httpx_execute_without_web_services_is_empty() {
        let tools = ToolConfig::default();
        let cancelled = AtomicBool::new(false);
        let execution = HttpxProvider
            .execute(
                "example.test",
                Capability::HttpProbing,
                &[],
                &context(&tools, &cancelled),
            )
            .unwrap();
        assert_eq!(execution.exit_status, Some(0));
        assert!(HttpxProvider.parse(&execution).unwrap().is_empty());
    }
    // --- Katana provider ---

    fn katana_exec(jsonl: &str) -> Execution {
        Execution {
            target: "https://app.example.test/".into(),
            capability: Capability::WebCrawling,
            command: vec!["katana".into()],
            stdout: jsonl.as_bytes().to_vec(),
            stderr: Vec::new(),
            exit_status: Some(0),
            pid: None,
            timed_out: false,
            started_at: crate::now(),
            ended_at: crate::now(),
            artifacts: Vec::new(),
            cancelled: false,
        }
    }

    #[test]
    fn katana_metadata_is_low_impact_web_crawling() {
        let metadata = KatanaProvider.metadata();
        assert_eq!(metadata.id, "katana");
        assert_eq!(metadata.risk_class, RiskClass::ActiveLowImpact);
        assert_eq!(metadata.capabilities, vec![Capability::WebCrawling]);
        assert_eq!(metadata.supported_target_types, vec![TargetType::URL]);
        assert_eq!(KatanaProvider.timeout(), Duration::from_secs(30));
    }

    #[test]
    fn katana_arguments_are_bounded_and_same_host() {
        let args = KatanaProvider::arguments("https://app.example.test/");
        let joined = args.join(" ");
        assert!(joined.contains("-d 2"));
        assert!(joined.contains("-fs fqdn"));
        assert!(joined.contains("-ct 20s"));
        assert!(joined.contains("-mrs 1048576"));
        assert!(!args
            .iter()
            .any(|a| matches!(a.as_str(), "-ns" | "-aff" | "-hl" | "-jc")));
    }

    #[test]
    fn katana_parses_only_same_host_urls() {
        let jsonl = concat!(
            r#"{"request":{"method":"GET","endpoint":"https://app.example.test/login"},"response":{"status_code":200}}"#,
            "\n",
            r#"{"request":{"method":"GET","endpoint":"https://app.example.test/api/users?x=1"}}"#,
            "\n",
            r#"{"request":{"method":"GET","endpoint":"https://outside.test/"}}"#,
            "\n",
            r#"{"request":{"method":"GET","endpoint":"https://app.example.test/login"}}"#,
            "\n",
            "not json\n"
        );
        let discoveries = KatanaProvider.parse(&katana_exec(jsonl)).unwrap();
        assert_eq!(discoveries.len(), 2);
        assert!(discoveries.iter().all(|d| d.asset_type == AssetType::URL));
        assert!(discoveries
            .iter()
            .all(|d| d.source.as_deref() == Some("https://app.example.test/")));
        assert!(discoveries
            .iter()
            .all(|d| d.relationship == Some(RelationshipType::HasEndpoint)));
        assert!(discoveries
            .iter()
            .all(|d| !d.value.contains("outside.test")));
    }

    #[test]
    fn katana_parses_local_targets_preserving_port_and_same_host_semantics() {
        // Same-host is defined by hostname (port-agnostic), matching public behavior:
        // a loopback literal is a *different* host from `localhost` and is dropped, but
        // another port on the same hostname is kept. No public DNS is involved.
        let jsonl = concat!(
            r#"{"request":{"method":"GET","endpoint":"http://localhost:3000/login"}}"#,
            "\n",
            r#"{"request":{"method":"GET","endpoint":"http://localhost:4000/other"}}"#,
            "\n",
            r#"{"request":{"method":"GET","endpoint":"http://127.0.0.1:3000/x"}}"#,
            "\n",
            r#"{"request":{"method":"GET","endpoint":"http://localhost:3000/login"}}"#,
            "\n",
        );
        let execution = Execution {
            target: "http://localhost:3000/".into(),
            capability: Capability::WebCrawling,
            command: vec!["katana".into()],
            stdout: jsonl.as_bytes().to_vec(),
            stderr: Vec::new(),
            exit_status: Some(0),
            pid: None,
            timed_out: false,
            started_at: crate::now(),
            ended_at: crate::now(),
            artifacts: Vec::new(),
            cancelled: false,
        };
        let values: Vec<_> = KatanaProvider
            .parse(&execution)
            .unwrap()
            .into_iter()
            .map(|d| d.value)
            .collect();
        assert!(values.contains(&"http://localhost:3000/login".to_string()));
        assert!(values.contains(&"http://localhost:4000/other".to_string())); // same hostname, other port
        assert!(!values.iter().any(|v| v.contains("127.0.0.1"))); // distinct host identity dropped
        assert_eq!(values.len(), 2);
    }

    #[test]
    fn katana_missing_executable_reports_missing() {
        let mut tools = ToolConfig::default();
        tools
            .overrides
            .insert("katana".into(), "/nonexistent/katana".into());
        assert_eq!(KatanaProvider.installation(&tools), Installation::Missing);
    }

    // --- Native HTTP analysis provider ---

    fn scope_entries() -> Vec<String> {
        vec!["example.test".into(), "*.example.test".into()]
    }

    fn run_native_http(
        transport: crate::web::StaticWebTransport,
        target: &str,
        scope: &[String],
    ) -> (serde_json::Value, Vec<Discovery>) {
        let provider = NativeHttpProvider::new(Arc::new(transport));
        let tools = ToolConfig::default();
        let cancelled = AtomicBool::new(false);
        let execution = provider
            .execute(
                target,
                Capability::WebAnalysis,
                &[],
                &context_scoped(&tools, &cancelled, scope),
            )
            .unwrap();
        let report: serde_json::Value = serde_json::from_slice(&execution.stdout).unwrap();
        let discoveries = provider.parse(&execution).unwrap();
        (report, discoveries)
    }

    #[test]
    fn native_http_metadata_is_builtin_low_impact() {
        let provider = NativeHttpProvider::new(Arc::new(crate::web::StaticWebTransport::new()));
        let m = provider.metadata();
        assert_eq!(m.id, "native_http");
        assert_eq!(m.risk_class, RiskClass::ActiveLowImpact);
        assert_eq!(m.capabilities, vec![Capability::WebAnalysis]);
        assert_eq!(m.supported_target_types, vec![TargetType::URL]);
        assert!(matches!(
            provider.installation(&ToolConfig::default()),
            Installation::BuiltIn
        ));
    }

    #[test]
    fn native_http_normalizes_headers_cors_and_enriches_website() {
        let transport = crate::web::StaticWebTransport::new()
            .with_response(
                "https://example.test/",
                200,
                &[
                    ("Server", "nginx"),
                    ("Content-Type", "text/html"),
                    ("Strict-Transport-Security", "max-age=63072000"),
                    ("Content-Security-Policy", "default-src 'self'"),
                    ("Access-Control-Allow-Origin", "*"),
                    ("Access-Control-Allow-Credentials", "true"),
                ],
                "<html></html>",
            )
            .with_response("https://example.test/robots.txt", 404, &[], "");
        let (report, discoveries) =
            run_native_http(transport, "https://example.test/", &scope_entries());
        assert_eq!(report["status"], json!(200));
        assert_eq!(report["server"], json!("nginx"));
        assert_eq!(
            report["security_headers"]["strict-transport-security"],
            json!("max-age=63072000")
        );
        assert_eq!(report["cors"]["access-control-allow-origin"], json!("*"));
        // Enriches the Website asset.
        assert_eq!(discoveries.len(), 1);
        assert_eq!(discoveries[0].asset_type, AssetType::Website);
        assert_eq!(discoveries[0].value, "https://example.test/");
        assert_eq!(discoveries[0].metadata["cors_present"], json!(true));
    }

    #[test]
    fn native_http_records_cookie_flags_but_never_values() {
        let transport = crate::web::StaticWebTransport::new().with_response(
            "https://example.test/",
            200,
            &[
                (
                    "Set-Cookie",
                    "sid=SUPERSECRETVALUE; Secure; HttpOnly; SameSite=Lax; Path=/",
                ),
                ("Set-Cookie", "theme=dark"),
            ],
            "",
        );
        let (report, _d) = run_native_http(transport, "https://example.test/", &scope_entries());
        let cookies = report["cookies"].as_array().unwrap();
        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0]["name"], json!("sid"));
        assert_eq!(cookies[0]["secure"], json!(true));
        assert_eq!(cookies[0]["http_only"], json!(true));
        assert_eq!(cookies[0]["same_site"], json!("Lax"));
        assert_eq!(cookies[1]["secure"], json!(false));
        // The secret cookie value must never appear anywhere in the report.
        let raw = serde_json::to_string(&report).unwrap();
        assert!(!raw.contains("SUPERSECRETVALUE"), "cookie value leaked");
    }

    #[test]
    fn native_http_follows_in_scope_redirects_and_scope_blocks_others() {
        // In-scope redirect is followed.
        let t1 = crate::web::StaticWebTransport::new()
            .with_response(
                "https://example.test/old",
                301,
                &[("Location", "https://api.example.test/new")],
                "",
            )
            .with_response(
                "https://api.example.test/new",
                200,
                &[("Server", "caddy")],
                "",
            )
            .with_response("https://example.test/robots.txt", 404, &[], "");
        let (report, _d) = run_native_http(t1, "https://example.test/old", &scope_entries());
        assert_eq!(report["final_url"], json!("https://api.example.test/new"));
        assert_eq!(report["redirects"][0]["followed"], json!(true));
        assert_eq!(report["status"], json!(200));

        // Out-of-scope redirect is NOT followed.
        let t2 = crate::web::StaticWebTransport::new()
            .with_response(
                "https://example.test/x",
                302,
                &[("Location", "https://evil.test/")],
                "",
            )
            .with_response("https://example.test/robots.txt", 404, &[], "");
        let (report, _d) = run_native_http(t2, "https://example.test/x", &scope_entries());
        assert_eq!(report["final_url"], json!("https://example.test/x"));
        assert_eq!(report["redirects"][0]["followed"], json!(false));
        assert!(report["notes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n.as_str().unwrap().contains("out-of-scope")));
    }

    #[test]
    fn native_http_parses_robots() {
        let transport = crate::web::StaticWebTransport::new()
            .with_response("https://example.test/", 200, &[], "")
            .with_response(
                "https://example.test/robots.txt",
                200,
                &[],
                "User-agent: *\nDisallow: /admin\nAllow: /public\nSitemap: https://example.test/sitemap.xml\n",
            );
        let (report, _d) = run_native_http(transport, "https://example.test/", &scope_entries());
        assert_eq!(report["robots"]["retrieved"], json!(true));
        assert_eq!(report["robots"]["records"]["disallow"][0], json!("/admin"));
        assert_eq!(
            report["robots"]["records"]["sitemaps"][0],
            json!("https://example.test/sitemap.xml")
        );
    }

    #[test]
    fn native_http_rejects_bad_scheme_and_credentials() {
        let provider = NativeHttpProvider::new(Arc::new(crate::web::StaticWebTransport::new()));
        let tools = ToolConfig::default();
        let cancelled = AtomicBool::new(false);
        let scope = scope_entries();
        // The credential URL is assembled so no credential literal appears in source.
        let credential_url = ["https://", "user:pass", "@example.test/"].concat();
        let bad = [
            "ftp://example.test/".to_string(),
            "file:///etc/passwd".to_string(),
            credential_url,
        ];
        for target in &bad {
            let err = provider
                .execute(
                    target,
                    Capability::WebAnalysis,
                    &[],
                    &context_scoped(&tools, &cancelled, &scope),
                )
                .unwrap_err();
            assert_eq!(err.code, "InvalidTarget", "accepted {target}");
        }
    }

    #[test]
    fn native_http_propagates_cancellation_and_timeout() {
        let tools = ToolConfig::default();
        let scope = scope_entries();
        // Cancellation.
        let provider = NativeHttpProvider::new(Arc::new(crate::web::StaticWebTransport::new()));
        let cancelled = AtomicBool::new(true);
        let err = provider
            .execute(
                "https://example.test/",
                Capability::WebAnalysis,
                &[],
                &context_scoped(&tools, &cancelled, &scope),
            )
            .unwrap_err();
        assert_eq!(err.code, "Cancelled");
        // Timeout on the primary request propagates.
        let provider = NativeHttpProvider::new(Arc::new(
            crate::web::StaticWebTransport::new().with_timeout("https://example.test/"),
        ));
        let ok = AtomicBool::new(false);
        let err = provider
            .execute(
                "https://example.test/",
                Capability::WebAnalysis,
                &[],
                &context_scoped(&tools, &ok, &scope),
            )
            .unwrap_err();
        assert_eq!(err.code, "ProviderTimeout");
    }

    // --- ffuf content discovery provider ---

    fn ffuf_exec(target: &str, json: &str) -> Execution {
        Execution {
            target: target.into(),
            capability: Capability::ContentDiscovery,
            command: vec!["ffuf".into()],
            stdout: json.as_bytes().to_vec(),
            stderr: Vec::new(),
            exit_status: Some(0),
            pid: None,
            timed_out: false,
            started_at: crate::now(),
            ended_at: crate::now(),
            artifacts: Vec::new(),
            cancelled: false,
        }
    }

    fn write_wordlist(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn ffuf_metadata_is_active_content_discovery() {
        let m = FfufProvider.metadata();
        assert_eq!(m.id, "ffuf");
        assert_eq!(m.risk_class, RiskClass::Active);
        assert_eq!(m.capabilities, vec![Capability::ContentDiscovery]);
        assert_eq!(m.supported_target_types, vec![TargetType::URL]);
        assert_eq!(FfufProvider.timeout(), Duration::from_secs(90));
    }

    #[test]
    fn ffuf_arguments_are_bounded_shell_free_and_no_recursion() {
        let args = FfufProvider::arguments(
            &FfufProvider::fuzz_url("https://example.test/"),
            "/tmp/w.txt",
        );
        assert_eq!(args.iter().filter(|a| *a == "-u").count(), 1);
        assert!(args
            .windows(2)
            .any(|w| w == ["-u", "https://example.test/FUZZ"]));
        assert!(args.windows(2).any(|w| w == ["-w", "/tmp/w.txt"]));
        assert!(args.windows(2).any(|w| w == ["-t", "10"]));
        assert!(args.windows(2).any(|w| w == ["-rate", "10"]));
        assert!(args.windows(2).any(|w| w == ["-timeout", "5"]));
        assert!(args.contains(&"-json".to_string()));
        // No recursion, no redirect following, no scope-disabling, no shell.
        assert!(!args
            .iter()
            .any(|a| a == "-recursion" || a == "-r" || a == "-no-scope" || a == "-x"));
        assert_eq!(
            FfufProvider::fuzz_url("https://example.test/app"),
            "https://example.test/app/FUZZ"
        );
    }

    #[test]
    fn ffuf_parses_discoveries_filters_404_and_offhost() {
        let json = r#"{"results":[
            {"url":"https://example.test/admin","status":200,"length":10,"redirectlocation":""},
            {"url":"https://example.test/admin","status":200,"length":10,"redirectlocation":""},
            {"url":"https://example.test/api","status":301,"length":0,"redirectlocation":"https://example.test/api/"},
            {"url":"https://example.test/missing","status":404,"length":0,"redirectlocation":""},
            {"url":"https://evil.test/x","status":200,"length":5,"redirectlocation":""}
        ]}"#;
        let discoveries = FfufProvider
            .parse(&ffuf_exec("https://example.test/", json))
            .unwrap();
        let values: Vec<_> = discoveries.iter().map(|d| d.value.as_str()).collect();
        assert_eq!(
            values,
            vec!["https://example.test/admin", "https://example.test/api"]
        ); // dedup, 404 + off-host dropped
        assert_eq!(discoveries[0].asset_type, AssetType::URL);
        assert_eq!(
            discoveries[0].relationship,
            Some(RelationshipType::HasEndpoint)
        );
        assert_eq!(
            discoveries[0].source.as_deref(),
            Some("https://example.test/")
        );
        assert_eq!(discoveries[0].metadata["status"], json!(200));
        assert_eq!(
            discoveries[1].metadata["redirect_location"],
            json!("https://example.test/api/")
        );
    }

    #[test]
    fn ffuf_parses_local_base_preserves_port_and_drops_offhost() {
        let json = r#"{"results":[
            {"url":"http://localhost:3000/admin","status":200,"length":10,"redirectlocation":""},
            {"url":"http://localhost:3000/secret","status":403,"length":20,"redirectlocation":""},
            {"url":"http://127.0.0.1:3000/x","status":200,"length":5,"redirectlocation":""},
            {"url":"http://localhost:3000/missing","status":404,"length":0,"redirectlocation":""}
        ]}"#;
        let discoveries = FfufProvider
            .parse(&ffuf_exec("http://localhost:3000/", json))
            .unwrap();
        let values: Vec<_> = discoveries.iter().map(|d| d.value.as_str()).collect();
        // Custom port preserved; 404 and the distinct loopback host dropped.
        assert_eq!(
            values,
            vec![
                "http://localhost:3000/admin",
                "http://localhost:3000/secret"
            ]
        );
        assert!(discoveries
            .iter()
            .all(|d| d.source.as_deref() == Some("http://localhost:3000/")));
    }

    #[test]
    fn ffuf_malformed_output_is_an_error() {
        assert!(FfufProvider
            .parse(&ffuf_exec("https://example.test/", "not json"))
            .is_err());
    }

    #[test]
    fn ffuf_missing_executable_reports_missing() {
        let mut tools = ToolConfig::default();
        tools
            .overrides
            .insert("ffuf".into(), "/nonexistent/ffuf".into());
        assert_eq!(FfufProvider.installation(&tools), Installation::Missing);
    }

    #[test]
    fn wordlist_validation_accepts_small_and_rejects_bad() {
        let dir = tempfile::tempdir().unwrap();
        // Valid: blanks + # comments ignored; 3 usable entries.
        let ok = write_wordlist(dir.path(), "ok.txt", "# comment\nadmin\n\nlogin\napi\n");
        assert_eq!(validate_wordlist(&ok).unwrap(), 3);
        // Empty (only blanks/comments).
        let empty = write_wordlist(dir.path(), "empty.txt", "# only a comment\n\n");
        assert_eq!(
            validate_wordlist(&empty).unwrap_err().code,
            "WordlistMissing"
        );
        // Too many entries.
        let many = write_wordlist(
            dir.path(),
            "many.txt",
            &"a\n".repeat(WORDLIST_MAX_ENTRIES + 1),
        );
        assert_eq!(
            validate_wordlist(&many).unwrap_err().code,
            "WordlistTooLarge"
        );
        // Overlong line.
        let longline = write_wordlist(
            dir.path(),
            "long.txt",
            &format!("{}\n", "a".repeat(WORDLIST_MAX_LINE_BYTES + 1)),
        );
        assert_eq!(
            validate_wordlist(&longline).unwrap_err().code,
            "WordlistTooLarge"
        );
        // Binary / NUL.
        let binary = dir.path().join("bin.txt");
        std::fs::write(&binary, [0u8, 1, 2, 3]).unwrap();
        assert_eq!(validate_wordlist(&binary).unwrap_err().code, "InvalidData");
        // Missing.
        assert_eq!(
            validate_wordlist(&dir.path().join("nope.txt"))
                .unwrap_err()
                .code,
            "WordlistMissing"
        );
    }

    #[test]
    fn ffuf_execute_requires_wordlist_option() {
        let tools = ToolConfig::default();
        let cancelled = AtomicBool::new(false);
        let err = FfufProvider
            .execute(
                "https://example.test/",
                Capability::ContentDiscovery,
                &[],
                &context(&tools, &cancelled),
            )
            .unwrap_err();
        assert_eq!(err.code, "WordlistMissing");
    }
}
