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
    PortDiscovery,
    ServiceFingerprinting,
    HttpProbing,
    WebCrawling,
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
                Arc::new(NmapProvider),
                Arc::new(HttpxProvider),
                Arc::new(KatanaProvider),
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
            // The synthetic provider does not model port discovery or HTTP probing.
            Capability::PortDiscovery | Capability::HttpProbing | Capability::WebCrawling => {}
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
        vec!["-d".into(), target.into(), "-silent".into(), "-oJ".into()]
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
        let report: DnsReport = serde_json::from_slice(&execution.stdout)
            .map_err(|_| CoreError::new("ProviderFailure", "Native DNS output is malformed."))?;
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

// ---------------------------------------------------------------------------
// Nmap provider (Phase 1C; first ACTIVE provider). Turns in-scope IPAddress
// assets into Port and Service assets via a conservative, unprivileged scan.
// Executes through the process supervisor with XML output; no NSE, no root.
// ---------------------------------------------------------------------------

pub struct NmapProvider;

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
    fn metadata(&self) -> ProviderMetadata {
        ProviderMetadata {
            id: "nmap".into(),
            name: "Nmap".into(),
            description:
                "Active port and service discovery via the external Nmap tool (unprivileged, no NSE)."
                    .into(),
            version: "external".into(),
            risk_class: RiskClass::Active,
            offline: false,
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
            Ok(outcome) => {
                let mut text = String::from_utf8_lossy(&outcome.stdout).into_owned();
                text.push('\n');
                text.push_str(&String::from_utf8_lossy(&outcome.stderr));
                let version = process::scan_version(&text).unwrap_or_else(|| "unknown".into());
                Installation::Installed { version }
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
            let document = roxmltree::Document::parse(chunk)
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
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    tech: Vec<String>,
}

impl HttpxProvider {
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
            let url = format!("{scheme}://{host}:{port}");
            if !urls.contains(&url) {
                urls.push(url);
            }
        }
        urls
    }
}

impl Provider for HttpxProvider {
    fn metadata(&self) -> ProviderMetadata {
        ProviderMetadata {
            id: "httpx".into(),
            name: "HTTPX".into(),
            description:
                "Low-impact HTTP/HTTPS probing of discovered web services via the external httpx tool."
                    .into(),
            version: "external".into(),
            risk_class: RiskClass::ActiveLowImpact,
            offline: false,
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
            Ok(outcome) => {
                let mut text = String::from_utf8_lossy(&outcome.stdout).into_owned();
                text.push('\n');
                text.push_str(&String::from_utf8_lossy(&outcome.stderr));
                let version = process::scan_version(&text).unwrap_or_else(|| "unknown".into());
                Installation::Installed { version }
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
            // asset). host may be "ip:port"; keep just the host for the source.
            let host = record
                .host
                .as_deref()
                .map(|h| h.rsplit_once(':').map(|(h, _)| h).unwrap_or(h).to_owned());
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
    fn metadata(&self) -> ProviderMetadata {
        ProviderMetadata {
            id: "katana".into(),
            name: "Katana".into(),
            description:
                "Bounded same-host web crawling via the external ProjectDiscovery Katana tool."
                    .into(),
            version: "external".into(),
            risk_class: RiskClass::ActiveLowImpact,
            offline: false,
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
            Ok(outcome) => {
                let mut text = String::from_utf8_lossy(&outcome.stdout).into_owned();
                text.push('\n');
                text.push_str(&String::from_utf8_lossy(&outcome.stderr));
                let version = process::scan_version(&text).unwrap_or_else(|| "unknown".into());
                Installation::Installed { version }
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
            .named("synthetic", Capability::SubdomainDiscovery)
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
        }
    }

    #[test]
    fn nmap_metadata_is_active_ports_services() {
        let metadata = NmapProvider.metadata();
        assert_eq!(metadata.id, "nmap");
        assert_eq!(metadata.risk_class, RiskClass::Active);
        assert!(!metadata.offline);
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
        assert!(v4.windows(2).any(|w| w == ["-oX", "-"]));
        assert!(!v4.contains(&"-6".to_string()));
        assert!(!v4
            .iter()
            .any(|a| a == "-A" || a == "-O" || a == "--script" || a == "-sS"));
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
        // roxmltree is non-validating and does not expand external/DTD entities.
        // A billion-laughs-style document must not blow up or expand into a service.
        let xml = concat!(
            "<?xml version=\"1.0\"?>",
            "<!DOCTYPE nmaprun [ <!ENTITY x \"aaaaaaaaaa\"> ]>",
            "<nmaprun><host><status state=\"up\"/><address addr=\"192.0.2.10\" addrtype=\"ipv4\"/>",
            "<ports><port protocol=\"tcp\" portid=\"80\"><state state=\"open\"/>",
            "<service name=\"&x;\"/></port></ports></host></nmaprun>",
        );
        // Either the parser rejects the DTD/entity, or it does not expand it; either
        // way there is no entity expansion and no panic.
        if let Ok(discoveries) = NmapProvider.parse(&nmap_exec(xml)) {
            assert!(discoveries.iter().all(|d| !d.value.contains("aaaaaaaaaa")));
        }
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
    fn katana_missing_executable_reports_missing() {
        let mut tools = ToolConfig::default();
        tools
            .overrides
            .insert("katana".into(), "/nonexistent/katana".into());
        assert_eq!(KatanaProvider.installation(&tools), Installation::Missing);
    }
}
