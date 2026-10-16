//! theHarvester (laramies/theHarvester, GPL-2.0, invoked as a separate executable) —
//! passive Domain OSINT over public sources.
//!
//! Verified against upstream source at release 4.11.1 (latest tag; Homebrew
//! `theharvester` formula 4.11.1) and the 4.10.x CLI. Behavior this integration
//! depends on:
//!
//! * Executable `theHarvester`; `theHarvester -h` prints a banner line
//!   `* theHarvester <X.Y.Z> … *` and the argparse help, then exits 0.
//! * `-d <domain> -b <sources> -l <limit> -q -f <name>` queries the selected
//!   sources and writes `<name>.json` (keys `emails`, `hosts`, `ips`, `asns`,
//!   `interesting_urls`, `people`, `linkedin_people`, `twitter_people`,
//!   `trello_urls`, `shodan`, `cmd`) plus `<name>.xml` (ignored). `hosts` entries
//!   are `host` or `host:ip` (sources that return passive-DNS pairs). `-q` skips
//!   reading the api-keys file.
//! * Active features are opt-in flags that MACSPLOIT **never** passes:
//!   `-r/--dns-resolve`, `-n/--dns-lookup` (reverse /24 sweep), `-c/--dns-brute`,
//!   `-t/--take-over`, `-s/--shodan`, `--screenshot`, `-a/--api-scan`, `-e`,
//!   `-p/--proxies`, and the vhost options. Without them theHarvester sends no DNS
//!   queries and never contacts the target or discovered hosts.
//! * Sources are an explicit allow-list of key-less, passive services present in
//!   4.10/4.11: certificate transparency (crtsh, certspotter), passive DNS /
//!   aggregators (hackertarget, otx, rapiddns, subdomaincenter, thc, urlscan),
//!   archives (waybackarchive), and one search engine (duckduckgo). Excluded:
//!   breach/infostealer sources (dehashed, haveibeenpwned, hudsonrock, leaklookup),
//!   API-key services, DNS-activity sources (shodan, subdomainfinderc99), and
//!   anything marked direct/active upstream.
//! * Upstream rotates browser User-Agent strings for some sources; MACSPLOIT does
//!   not add proxy rotation or any other evasion.
//!
//! Normalization: hosts inside the domain become `Subdomain` assets (deduplicated
//! with Subfinder/CT), `host:ip` pairs add `IPAddress` assets via `observed_ip`
//! (not `resolves_to` — MACSPLOIT did not resolve them), emails at the domain (or a
//! subdomain) become `EmailAddress` assets via `has_email`. People names, social
//! links, and URLs are only counted (minimization); the raw report is evidence.

use super::osint_cli::{self, REPORT_CAP, STDERR_CAP, STDOUT_CAP};
use super::{
    Capability, Execution, NetworkActivity, ParsedOutput, Provider, ProviderContext,
    ProviderMetadata, ProviderSetup, RiskClass,
};
use crate::{
    assets::{Asset, Discovery},
    error::{CoreError, Result},
    osint::domain::{self, DomainFindings, RunFraming},
    process::{self, Installation, RunOptions, ToolConfig},
    targets::TargetType,
};
use serde_json::{json, Map, Value};
use std::{
    path::PathBuf,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

pub struct TheHarvesterProvider;

pub const THEHARVESTER_TOOL: &str = "theHarvester";
pub const THEHARVESTER_ID: &str = "theharvester";
pub const RUN_TIMEOUT: Duration = Duration::from_secs(300);
/// Upstream series whose CLI and JSON report were verified.
pub const SUPPORTED_SERIES: &[&str] = &["4.10.", "4.11."];
/// The fixed, reviewed passive source allow-list.
pub const SOURCES: &[&str] = &[
    "certspotter",
    "crtsh",
    "duckduckgo",
    "hackertarget",
    "otx",
    "rapiddns",
    "subdomaincenter",
    "thc",
    "urlscan",
    "waybackarchive",
];
/// Per-source result limit passed with `-l`.
pub const RESULT_LIMIT: u32 = 500;
/// Report basename (relative to the private working directory).
const REPORT_NAME: &str = "report";
const REPORT_ARTIFACT: &str = "theharvester_json";
/// Entries considered per report list.
const MAX_LIST_ENTRIES: usize = 5000;

impl TheHarvesterProvider {
    /// The exact, bounded, passive-only argument array.
    pub fn arguments(domain: &str) -> Vec<String> {
        vec![
            "-d".into(),
            domain.into(),
            "-b".into(),
            SOURCES.join(","),
            "-l".into(),
            RESULT_LIMIT.to_string(),
            "-q".into(),
            "-f".into(),
            REPORT_NAME.into(),
        ]
    }

    fn locate(tools: &ToolConfig) -> Option<PathBuf> {
        osint_cli::locate(tools, THEHARVESTER_TOOL)
    }

    fn subject(target: &str, capability: Capability) -> Result<String> {
        super::passive_web::domain_subject(target, capability, "theHarvester")
    }
}

fn list<'a>(report: &'a Map<String, Value>, key: &str) -> impl Iterator<Item = &'a str> {
    report
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_LIST_ENTRIES)
        .filter_map(Value::as_str)
}

fn count(report: &Map<String, Value>, key: &str) -> usize {
    match report.get(key) {
        Some(Value::Array(items)) => items.len(),
        Some(Value::Object(items)) => items.len(),
        _ => 0,
    }
}

impl Provider for TheHarvesterProvider {
    fn setup(&self) -> Option<ProviderSetup> {
        Some(ProviderSetup {
            install_command: Some("brew install theharvester".into()),
            homepage: Some("https://github.com/laramies/theHarvester".into()),
            documentation: Some(
                "https://github.com/laramies/theHarvester/blob/master/README.md".into(),
            ),
        })
    }

    fn metadata(&self) -> ProviderMetadata {
        ProviderMetadata {
            id: THEHARVESTER_ID.into(),
            name: "theHarvester".into(),
            description: "Passive domain OSINT from a fixed allow-list of key-less public sources (certificate transparency, passive DNS, archives, one search engine): hosts, emails, and passive IPs. No DNS resolution, brute force, takeover checks, screenshots, or breach sources.".into(),
            version: "external".into(),
            capabilities: vec![Capability::DomainOsint],
            supported_target_types: vec![TargetType::Domain],
            risk_class: RiskClass::Passive,
            network_activity: NetworkActivity::Network,
        }
    }

    fn installation(&self, tools: &ToolConfig) -> Installation {
        let Some(executable) = Self::locate(tools) else {
            return Installation::Missing;
        };
        let Ok(dir) = osint_cli::private_dir("macsploit-theharvester-") else {
            return Installation::ExecutionError {
                message: "Could not prepare a private directory for the version probe.".into(),
            };
        };
        let cancelled = AtomicBool::new(false);
        match process::run_with(
            &executable,
            &["-h".into()],
            &cancelled,
            Instant::now() + Duration::from_secs(20),
            STDOUT_CAP,
            STDERR_CAP,
            &RunOptions {
                env: osint_cli::base_env(dir.path()),
                current_dir: Some(dir.path().to_path_buf()),
            },
        ) {
            Ok(outcome) if outcome.timed_out || outcome.exit_status != Some(0) => {
                Installation::ExecutionError {
                    message: "The provider version probe failed or timed out.".into(),
                }
            }
            Ok(outcome) => {
                let text = String::from_utf8_lossy(&outcome.stdout);
                let version = text
                    .lines()
                    .filter(|l| l.contains("theHarvester"))
                    .find_map(process::scan_version);
                osint_cli::classify_version_series(version, SUPPORTED_SERIES, executable)
            }
            Err(error) => Installation::ExecutionError {
                message: error.message,
            },
        }
    }

    fn timeout(&self) -> Duration {
        RUN_TIMEOUT
    }

    fn execute(
        &self,
        target: &str,
        capability: Capability,
        _inputs: &[Asset],
        ctx: &ProviderContext,
    ) -> Result<Execution> {
        let started_at = crate::now();
        let domain = Self::subject(target, capability)?;
        let executable = Self::locate(ctx.tools).ok_or_else(|| {
            CoreError::new(
                "ProviderMissing",
                "theHarvester is not installed. Install it (brew install theharvester) and refresh providers.",
            )
        })?;
        let dir = osint_cli::private_dir("macsploit-theharvester-")?;
        let args = Self::arguments(&domain);
        let outcome = process::run_with(
            &executable,
            &args,
            ctx.cancelled,
            ctx.deadline,
            STDOUT_CAP,
            STDERR_CAP,
            &RunOptions {
                env: osint_cli::base_env(dir.path()),
                current_dir: Some(dir.path().to_path_buf()),
            },
        )?;
        let report = dir.path().join(format!("{REPORT_NAME}.json"));
        let artifacts = osint_cli::capture_file(REPORT_ARTIFACT, &report, REPORT_CAP)
            .into_iter()
            .collect();
        let mut command = vec![executable.to_string_lossy().into_owned()];
        command.extend(args);
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
            artifacts,
            cancelled: outcome.cancelled,
        })
    }

    fn parse(&self, execution: &Execution) -> Result<Vec<Discovery>> {
        Ok(self.parse_outcome(execution)?.discoveries)
    }

    fn parse_outcome(&self, execution: &Execution) -> Result<ParsedOutput> {
        let domain = Self::subject(&execution.target, execution.capability)?;
        let bytes = osint_cli::report_bytes(
            execution,
            REPORT_ARTIFACT,
            "theHarvester did not write its JSON report; raw output is preserved as evidence.",
        )?;
        let value: Value = serde_json::from_slice(bytes).map_err(|_| {
            CoreError::new(
                "ProviderFailure",
                "theHarvester's JSON report is malformed; raw output is preserved as evidence.",
            )
        })?;
        let report = value.as_object().ok_or_else(|| {
            CoreError::new(
                "ProviderFailure",
                "theHarvester's JSON report is not an object; raw output is preserved as evidence.",
            )
        })?;
        let mut findings = DomainFindings::new(&domain);
        let mut malformed = 0usize;
        for entry in list(report, "hosts") {
            match entry.split_once(':') {
                Some((host, ip)) => {
                    let kept = findings.add_host(host, Map::new());
                    if kept.is_some() || host.trim().eq_ignore_ascii_case(&domain) {
                        let mut facts = Map::new();
                        facts.insert("reported_for".into(), domain::text_fact(host));
                        findings.add_ip(ip, kept.as_deref(), facts);
                    }
                }
                None => {
                    findings.add_host(entry, Map::new());
                }
            }
        }
        for ip in list(report, "ips") {
            findings.add_ip(ip, None, Map::new());
        }
        for email in list(report, "emails") {
            findings.add_email(email, Map::new());
        }
        for key in ["hosts", "ips", "emails", "asns"] {
            if report.get(key).is_some_and(|v| !v.is_array()) {
                malformed += 1;
            }
        }
        let asns: Vec<&str> = list(report, "asns").collect();
        let mut extra = Map::new();
        extra.insert("source".into(), json!("theHarvester"));
        extra.insert("sources_queried".into(), json!(SOURCES));
        extra.insert(
            "theharvester".into(),
            json!({
                "asns": domain::text_list(asns.iter().copied(), 20),
                // Counted only (minimization): never stored as assets.
                "people_counted": count(report, "people")
                    + count(report, "linkedin_people")
                    + count(report, "twitter_people"),
                "links_counted": count(report, "linkedin_links") + count(report, "trello_urls"),
                "urls_counted": count(report, "interesting_urls"),
                "report_fields_malformed": malformed,
            }),
        );
        Ok(domain::build_domain_output(
            findings,
            RunFraming {
                provider_id: THEHARVESTER_ID,
                historical: false,
                note: domain::PASSIVE_NOTE,
                subject_facts: Map::new(),
                extra,
                provider_partial: malformed > 0,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assets::{AssetType, RelationshipType};
    use crate::providers::ExecutionArtifact;

    fn exec(report: Option<&str>) -> Execution {
        Execution {
            target: "example.test".into(),
            capability: Capability::DomainOsint,
            command: vec![],
            stdout: vec![],
            stderr: vec![],
            exit_status: Some(0),
            pid: None,
            timed_out: false,
            started_at: String::new(),
            ended_at: String::new(),
            artifacts: report
                .map(|r| ExecutionArtifact {
                    name: REPORT_ARTIFACT.into(),
                    bytes: r.as_bytes().to_vec(),
                    observed_bytes: Some(r.len() as u64),
                    over_limit: false,
                })
                .into_iter()
                .collect(),
            cancelled: false,
        }
    }

    #[test]
    fn arguments_are_passive_only_and_fixed() {
        let args = TheHarvesterProvider::arguments("example.test");
        assert_eq!(&args[..2], ["-d", "example.test"]);
        for forbidden in [
            "-r",
            "--dns-resolve",
            "-n",
            "--dns-lookup",
            "-c",
            "--dns-brute",
            "-t",
            "--take-over",
            "-s",
            "--shodan",
            "--screenshot",
            "-a",
            "--api-scan",
            "-e",
            "-p",
            "--proxies",
            "--vhost",
        ] {
            assert!(!args.iter().any(|a| a == forbidden), "{forbidden}");
        }
        let sources = &args[args.iter().position(|a| a == "-b").unwrap() + 1];
        for excluded in [
            "dehashed",
            "haveibeenpwned",
            "hudsonrock",
            "leaklookup",
            "shodan",
            "all",
        ] {
            assert!(!sources.split(',').any(|s| s == excluded), "{excluded}");
        }
        let meta = TheHarvesterProvider.metadata();
        assert_eq!(meta.risk_class, RiskClass::Passive);
        assert_eq!(meta.capabilities, vec![Capability::DomainOsint]);
    }

    #[test]
    fn report_maps_hosts_pairs_ips_and_scoped_emails() {
        let report = r#"{"cmd":"-d example.test","hosts":["api.example.test","API.example.test:192.0.2.10","mail.example.test:2001:db8::1","example.test:192.0.2.1","cdn.other.test:198.51.100.1","bad host"],
          "ips":["192.0.2.20","not-an-ip"],"emails":["person@example.test","Person@EXAMPLE.test","x@other.test"],
          "asns":["AS64500"],"people":["Jane Example"],"interesting_urls":["https://example.test/a"],"shodan":[]}"#;
        let out = TheHarvesterProvider
            .parse_outcome(&exec(Some(report)))
            .unwrap();
        let subdomains: Vec<_> = out
            .discoveries
            .iter()
            .filter(|d| d.asset_type == AssetType::Subdomain)
            .map(|d| d.value.as_str())
            .collect();
        assert_eq!(subdomains, ["api.example.test", "mail.example.test"]);
        let ip = |v: &str| out.discoveries.iter().find(|d| d.value == v).unwrap();
        assert_eq!(ip("192.0.2.10").source.as_deref(), Some("api.example.test"));
        assert_eq!(
            ip("192.0.2.10").relationship,
            Some(RelationshipType::ObservedIp)
        );
        assert_eq!(
            ip("2001:db8::1").source.as_deref(),
            Some("mail.example.test")
        );
        assert_eq!(ip("192.0.2.1").source.as_deref(), Some("example.test"));
        assert_eq!(ip("192.0.2.20").source.as_deref(), Some("example.test"));
        assert!(
            !out.discoveries.iter().any(|d| d.value == "198.51.100.1"),
            "out-of-domain pair dropped"
        );
        let emails: Vec<_> = out
            .discoveries
            .iter()
            .filter(|d| d.asset_type == AssetType::EmailAddress)
            .map(|d| (d.value.as_str(), d.relationship))
            .collect();
        assert_eq!(
            emails,
            [
                ("Person@example.test", Some(RelationshipType::HasEmail)),
                ("person@example.test", Some(RelationshipType::HasEmail))
            ]
        );
        let summary = out.summary.unwrap();
        assert_eq!(summary["theharvester"]["people_counted"], 1);
        assert_eq!(summary["theharvester"]["urls_counted"], 1);
        assert!(
            !summary.to_string().contains("Jane Example"),
            "people are never stored"
        );
        assert_eq!(summary["counts"]["dropped_out_of_domain"], 2);
    }

    #[test]
    fn missing_malformed_and_oversized_reports_fail_cleanly() {
        assert_eq!(
            TheHarvesterProvider
                .parse_outcome(&exec(None))
                .unwrap_err()
                .code,
            "ProviderFailure"
        );
        for bad in ["{oops", "[]"] {
            assert_eq!(
                TheHarvesterProvider
                    .parse_outcome(&exec(Some(bad)))
                    .unwrap_err()
                    .code,
                "ProviderFailure"
            );
        }
        let mut over = exec(Some("{}"));
        over.artifacts[0].over_limit = true;
        over.artifacts[0].bytes.clear();
        assert_eq!(
            TheHarvesterProvider.parse_outcome(&over).unwrap_err().code,
            "BudgetExceeded"
        );
        // Wrong field types are tolerated but make the run partial.
        let out = TheHarvesterProvider
            .parse_outcome(&exec(Some(r#"{"hosts":"api.example.test"}"#)))
            .unwrap();
        assert!(out.partial);
        // An empty report is a clean zero-result run.
        let out = TheHarvesterProvider
            .parse_outcome(&exec(Some(r#"{"hosts":[]}"#)))
            .unwrap();
        assert_eq!(out.discoveries.len(), 1);
        assert!(!out.partial);
    }
}
