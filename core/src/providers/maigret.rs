//! Maigret (soxoj/maigret, MIT) — Username OSINT provider.
//!
//! Verified against the upstream `maigret` CLI. Behavior this integration depends on:
//!
//! * Executable: the `maigret` console script (`pipx install maigret`).
//! * Version: `maigret --version` prints a version banner and exits.
//! * Subject: a single positional username (strictly validated here).
//! * Structured output: `--json simple -fo <dir>` writes `report_<username>_simple.json`
//!   into the output folder — a JSON object keyed by site name where **only claimed
//!   (found) sites appear**; each value has `url_main`, `url_user`, a `status` field,
//!   and optional `ids_data`. We locate the file by its `simple.json` suffix in the
//!   private run folder. The report is written when the scan finishes; a cancelled/
//!   timed-out run has none (stdout/stderr are still kept as evidence).
//! * Bounded/safe modes: `--no-recursion --no-extracting` disable identifier pivots;
//!   `--top-sites 500` and `--timeout`/`--retries` bound the run. Never passed:
//!   `-a/--all-sites`, `--permute`, `--parse` (recursive), `--proxy`/`--tor-proxy`,
//!   `--cloudflare-bypass`, `--ai`.

use super::osint_cli::{self, REPORT_CAP, STDERR_CAP, STDOUT_CAP};
use super::{
    Capability, Execution, NetworkActivity, ParsedOutput, Provider, ProviderContext,
    ProviderMetadata, ProviderSetup, RiskClass,
};
use crate::{
    assets::{Asset, Discovery},
    error::{CoreError, Result},
    osint::{self, CheckStatus, OsintCheck, ParseStats, Subject},
    process::{self, Installation, RunOptions, ToolConfig},
    targets::TargetType,
};
use serde_json::{Map, Value};
use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

pub struct MaigretProvider;

pub const MAIGRET_TOOL: &str = "maigret";
pub const REPORT_ARTIFACT: &str = "maigret_simple_json";
pub const REQUEST_TIMEOUT_SECS: u32 = 10;
pub const RETRIES: u32 = 1;
/// Bounded number of top sites scanned (upstream default is 500; `-a` is ~5,900).
pub const TOP_SITES: u32 = 500;
pub const RUN_TIMEOUT: Duration = Duration::from_secs(600);
/// Upstream versions whose CLI/JSON schema were verified (0.x series).
pub const SUPPORTED_SERIES: &str = "0.";

impl MaigretProvider {
    /// The exact, bounded argument array. The report is written into `folder`.
    pub fn arguments(subject: &Subject, folder: &str) -> Vec<String> {
        vec![
            subject.query.clone(),
            "--json".into(),
            "simple".into(),
            "-fo".into(),
            folder.into(),
            "--no-recursion".into(),
            "--no-extracting".into(),
            "--top-sites".into(),
            TOP_SITES.to_string(),
            "--timeout".into(),
            REQUEST_TIMEOUT_SECS.to_string(),
            "--retries".into(),
            RETRIES.to_string(),
        ]
    }

    fn locate(tools: &ToolConfig) -> Option<PathBuf> {
        osint_cli::locate(tools, MAIGRET_TOOL)
    }

    /// Find the `*_simple.json` report maigret wrote in the output folder.
    fn find_report(folder: &Path) -> Option<PathBuf> {
        let mut candidates: Vec<PathBuf> = std::fs::read_dir(folder)
            .ok()?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.ends_with("simple.json"))
                    .unwrap_or(false)
            })
            .collect();
        candidates.sort();
        candidates.into_iter().next()
    }

    /// The upstream status for a site entry. `simple` JSON contains only claimed
    /// sites, so a present entry defaults to Positive; a nested status label is
    /// honored when available.
    fn site_status(entry: &Map<String, Value>) -> (CheckStatus, String) {
        let label = match entry.get("status") {
            Some(Value::String(text)) => serde_json::from_str::<Value>(text)
                .ok()
                .and_then(|v| v.get("status").and_then(Value::as_str).map(str::to_owned)),
            Some(Value::Object(status)) => status
                .get("status")
                .and_then(Value::as_str)
                .map(str::to_owned),
            _ => None,
        };
        match label.as_deref() {
            Some("Claimed") | None => (CheckStatus::Positive, "Claimed".into()),
            Some("Available") => (CheckStatus::Negative, "Available".into()),
            Some(other) => (
                CheckStatus::Positive,
                osint::clean_text(other, osint::MAX_KEY_BYTES),
            ),
        }
    }

    fn check(site: &str, entry: &Value) -> Option<OsintCheck> {
        let entry = entry.as_object()?;
        let platform = osint::clean_text(site, osint::MAX_FIELD_BYTES);
        let platform_key = osint::platform_key(&platform)?;
        let (status, upstream_status) = Self::site_status(entry);
        let raw_url = entry.get("url_user").and_then(Value::as_str).unwrap_or("");
        let url = osint::safe_url(raw_url);
        let empty = Map::new();
        let profile = entry
            .get("ids_data")
            .and_then(Value::as_object)
            .unwrap_or(&empty);
        Some(OsintCheck {
            status,
            platform,
            platform_key,
            category: None,
            upstream_status,
            url_rejected: !raw_url.trim().is_empty() && url.is_none(),
            url,
            reason: None,
            profile: osint::bounded_profile(profile),
            media: Map::new(),
            upstream_confidence: None,
        })
    }
}

impl Provider for MaigretProvider {
    fn setup(&self) -> Option<ProviderSetup> {
        Some(ProviderSetup {
            install_command: Some("pipx install maigret".into()),
            homepage: Some("https://github.com/soxoj/maigret".into()),
            documentation: Some("https://maigret.readthedocs.io/".into()),
        })
    }

    fn metadata(&self) -> ProviderMetadata {
        ProviderMetadata {
            id: "maigret".into(),
            name: "Maigret".into(),
            description: "Username OSINT: checks public platforms for one explicitly selected username using a bounded top-sites scan (no recursion, no identifier extraction, no proxies).".into(),
            version: "external".into(),
            capabilities: vec![Capability::UsernameOsint],
            supported_target_types: vec![TargetType::Username],
            risk_class: RiskClass::ActiveLowImpact,
            network_activity: NetworkActivity::Network,
        }
    }

    fn installation(&self, tools: &ToolConfig) -> Installation {
        let Some(executable) = Self::locate(tools) else {
            return Installation::Missing;
        };
        let Ok(dir) = osint_cli::private_dir("macsploit-maigret-") else {
            return Installation::ExecutionError {
                message: "Could not prepare a private directory for the version probe.".into(),
            };
        };
        let cancelled = AtomicBool::new(false);
        match process::run_with(
            &executable,
            &["--version".into()],
            &cancelled,
            Instant::now() + Duration::from_secs(15),
            STDERR_CAP,
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
                let version = text.lines().find_map(process::scan_version);
                osint_cli::classify_version(version, SUPPORTED_SERIES, executable)
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
        let subject = osint_cli::username_subject(target, capability)?;
        let executable = Self::locate(ctx.tools).ok_or_else(|| {
            CoreError::new(
                "ProviderMissing",
                "Maigret is not installed. Install it (pipx install maigret) and refresh providers.",
            )
        })?;
        let dir = osint_cli::private_dir("macsploit-maigret-")?;
        let args = Self::arguments(&subject, &dir.path().to_string_lossy());
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
        let artifacts = Self::find_report(dir.path())
            .and_then(|report| osint_cli::capture_file(REPORT_ARTIFACT, &report, REPORT_CAP))
            .into_iter()
            .collect();
        let mut command = vec![executable.to_string_lossy().into_owned()];
        command.extend(Self::arguments(&subject, "<private-run-dir>"));
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
        let subject = osint_cli::username_subject(&execution.target, execution.capability)?;
        let bytes = osint_cli::report_bytes(
            execution,
            REPORT_ARTIFACT,
            "Maigret did not write its JSON report.",
        )?;
        let report: Value = serde_json::from_slice(bytes)
            .map_err(|_| CoreError::new("ProviderFailure", "Maigret JSON output is malformed."))?;
        let sites = report.as_object().ok_or_else(|| {
            CoreError::new(
                "ProviderFailure",
                "Maigret JSON output is not a site-keyed object.",
            )
        })?;
        let mut stats = ParseStats {
            dropped_over_limit: sites.len().saturating_sub(osint::MAX_RECORDS),
            ..ParseStats::default()
        };
        let mut checks = Vec::new();
        for (site, entry) in sites.iter().take(osint::MAX_RECORDS) {
            match Self::check(site, entry) {
                Some(check) => checks.push(check),
                None => stats.malformed += 1,
            }
        }
        Ok(osint::build_output("maigret", &subject, checks, stats))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assets::{AssetType, RelationshipType};
    use crate::providers::ExecutionArtifact;

    fn subject(value: &str) -> Subject {
        Subject::from_target(TargetType::Username, value).unwrap()
    }

    fn exec(target: &str, json: Option<&str>) -> Execution {
        Execution {
            target: target.into(),
            capability: Capability::UsernameOsint,
            command: vec!["maigret".into()],
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_status: Some(0),
            pid: None,
            timed_out: false,
            started_at: crate::now(),
            ended_at: crate::now(),
            artifacts: json
                .map(|j| ExecutionArtifact {
                    name: REPORT_ARTIFACT.into(),
                    bytes: j.as_bytes().to_vec(),
                    observed_bytes: Some(j.len() as u64),
                    over_limit: false,
                })
                .into_iter()
                .collect(),
            cancelled: false,
        }
    }

    #[test]
    fn metadata_is_username_osint_only() {
        let m = MaigretProvider.metadata();
        assert_eq!(m.id, "maigret");
        assert_eq!(m.capabilities, vec![Capability::UsernameOsint]);
        assert_eq!(m.supported_target_types, vec![TargetType::Username]);
        assert_eq!(
            MaigretProvider.setup().unwrap().install_command.as_deref(),
            Some("pipx install maigret")
        );
    }

    #[test]
    fn arguments_bound_the_scan_and_disable_pivots() {
        let args = MaigretProvider::arguments(&subject("@octo"), "/out");
        assert_eq!(args[0], "octo");
        assert!(args.contains(&"--no-recursion".to_owned()));
        assert!(args.contains(&"--no-extracting".to_owned()));
        assert!(args.contains(&"--top-sites".to_owned()));
        for forbidden in [
            "-a",
            "--all-sites",
            "--permute",
            "--parse",
            "--proxy",
            "--cloudflare-bypass",
        ] {
            assert!(!args.iter().any(|a| a == forbidden), "{forbidden}");
        }
    }

    #[test]
    fn parses_claimed_sites_with_profile_and_url() {
        let json = r#"{
          "GitHub": {"url_main":"https://github.com","url_user":"https://github.com/octo","status":"{\"status\": \"Claimed\"}","ids_data":{"name":"Octo","uid":"42","nested":{"x":1}}},
          "X (Twitter)": {"url_main":"https://x.com","url_user":"https://x.com/octo","status":{"status":"Claimed"}}
        }"#;
        let out = MaigretProvider
            .parse_outcome(&exec("@octo", Some(json)))
            .unwrap();
        assert!(!out.partial);
        let s = out.summary.clone().unwrap();
        assert_eq!(s["counts"]["positive"], 2);
        assert_eq!(s["accounts"], 2);
        let account = out
            .discoveries
            .iter()
            .find(|d| d.value == "github:octo")
            .unwrap();
        assert_eq!(account.asset_type, AssetType::Account);
        assert_eq!(account.relationship, Some(RelationshipType::HasAccount));
        let obs = account.observation.as_ref().unwrap();
        assert_eq!(obs.metadata["provider"], "maigret");
        assert_eq!(obs.metadata["profile"]["name"], "Octo");
        assert_eq!(obs.metadata["profile"]["uid"], "42");
        assert!(obs.metadata["profile"].get("nested").is_none());
        assert!(out
            .discoveries
            .iter()
            .any(|d| d.asset_type == AssetType::URL && d.value == "https://github.com/octo"));
    }

    #[test]
    fn empty_report_yields_only_the_subject() {
        let out = MaigretProvider
            .parse_outcome(&exec("@ghost", Some("{}")))
            .unwrap();
        assert_eq!(out.discoveries.len(), 1);
        assert_eq!(out.discoveries[0].asset_type, AssetType::Username);
        assert!(!out.partial);
    }

    #[test]
    fn malformed_and_missing_reports_are_errors() {
        assert_eq!(
            MaigretProvider
                .parse_outcome(&exec("@octo", Some("{not json")))
                .unwrap_err()
                .code,
            "ProviderFailure"
        );
        assert_eq!(
            MaigretProvider
                .parse_outcome(&exec("@octo", Some("[1,2,3]")))
                .unwrap_err()
                .code,
            "ProviderFailure"
        );
        assert_eq!(
            MaigretProvider
                .parse_outcome(&exec("@octo", None))
                .unwrap_err()
                .code,
            "ProviderFailure"
        );
    }

    #[test]
    fn missing_executable_reports_missing() {
        let mut tools = ToolConfig::default();
        tools
            .overrides
            .insert(MAIGRET_TOOL.into(), "/nonexistent/maigret".into());
        assert_eq!(MaigretProvider.installation(&tools), Installation::Missing);
    }
}
