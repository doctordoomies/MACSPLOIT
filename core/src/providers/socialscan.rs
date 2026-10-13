//! socialscan (iojw/socialscan, MIT) — Username OSINT provider.
//!
//! Verified against the upstream `socialscan` CLI. Behavior this integration depends on:
//!
//! * Executable: the `socialscan` console script (`pip install socialscan`).
//! * Version: `socialscan --version` prints `socialscan <X.Y.Z>` and exits.
//! * Subject: one positional query (username; strictly validated here).
//! * Structured output: `--json <file>` writes a JSON object keyed by platform (we
//!   pass `--view-by platform`) whose values are lists of per-platform records:
//!   `{query, platform, available, valid, success, message, link?}` (null fields are
//!   omitted; `link` only with `--show-urls`). socialscan reports *registration
//!   availability*: `available=false` with `valid=true` and `success=true` means the
//!   identifier is taken (registered) — a positive OSINT result. It performs only
//!   public availability checks (never login, credential, or private-data access).
//! * Never passed: `--available-only` (we want taken results), `--proxy-list`,
//!   `--cache-tokens`, `--input` (file inputs).
//!
//! socialscan is less actively maintained than the other providers; its platform
//! coverage is smaller and may drift. It is integrated for the public-registration
//! signal it still provides, and uncertainty is preserved like any other provider.

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
    path::PathBuf,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

pub struct SocialscanProvider;

pub const SOCIALSCAN_TOOL: &str = "socialscan";
pub const REPORT_ARTIFACT: &str = "socialscan_json";
pub const RUN_TIMEOUT: Duration = Duration::from_secs(300);
/// Upstream versions whose CLI/JSON schema were verified (1.x series).
pub const SUPPORTED_SERIES: &str = "1.";

impl SocialscanProvider {
    /// The exact, bounded argument array. The report is written to `output`.
    pub fn arguments(subject: &Subject, output: &str) -> Vec<String> {
        vec![
            subject.query.clone(),
            "--json".into(),
            output.into(),
            "--show-urls".into(),
            "--view-by".into(),
            "platform".into(),
        ]
    }

    fn locate(tools: &ToolConfig) -> Option<PathBuf> {
        osint_cli::locate(tools, SOCIALSCAN_TOOL)
    }

    /// Map socialscan's availability booleans to a provider-neutral status and a
    /// short upstream label. A taken (registered) identifier is a positive result.
    fn classify(record: &Map<String, Value>) -> (CheckStatus, String) {
        let flag = |key: &str| record.get(key).and_then(Value::as_bool);
        let success = flag("success").unwrap_or(false);
        let available = flag("available");
        let valid = flag("valid").unwrap_or(true);
        if !success {
            return (CheckStatus::Error, "error".into());
        }
        match available {
            Some(true) => (CheckStatus::Negative, "available".into()),
            Some(false) if valid => (CheckStatus::Positive, "taken".into()),
            // Reported unavailable but the identifier is not valid for this platform —
            // ambiguous, never counted as a confirmed account.
            Some(false) => (CheckStatus::Unknown, "invalid".into()),
            None => (CheckStatus::Unknown, "unknown".into()),
        }
    }

    fn check(record: &Value) -> Option<OsintCheck> {
        let record = record.as_object()?;
        let platform = osint::clean_text(
            record.get("platform").and_then(Value::as_str)?,
            osint::MAX_FIELD_BYTES,
        );
        let platform_key = osint::platform_key(&platform)?;
        let (status, upstream_status) = Self::classify(record);
        let raw_url = record.get("link").and_then(Value::as_str).unwrap_or("");
        let url = osint::safe_url(raw_url);
        let reason = record
            .get("message")
            .and_then(Value::as_str)
            .map(|v| osint::clean_text(v, osint::MAX_FIELD_BYTES))
            .filter(|v| !v.is_empty());
        Some(OsintCheck {
            status,
            platform,
            platform_key,
            category: None,
            upstream_status,
            url_rejected: !raw_url.trim().is_empty() && url.is_none(),
            url,
            reason,
            profile: Map::new(),
            media: Map::new(),
            upstream_confidence: None,
        })
    }

    /// socialscan query values this record is about (for subject attribution).
    fn record_query(record: &Value) -> Option<String> {
        record
            .as_object()?
            .get("query")
            .and_then(Value::as_str)
            .map(str::to_owned)
    }
}

impl Provider for SocialscanProvider {
    fn setup(&self) -> Option<ProviderSetup> {
        Some(ProviderSetup {
            install_command: Some("pip install socialscan".into()),
            homepage: Some("https://github.com/iojw/socialscan".into()),
            documentation: Some("https://github.com/iojw/socialscan#usage".into()),
        })
    }

    fn metadata(&self) -> ProviderMetadata {
        ProviderMetadata {
            id: "socialscan".into(),
            name: "socialscan".into(),
            description: "Username OSINT: checks public registration availability for one explicitly selected username across a small set of platforms (availability only — never login, credentials, or private data).".into(),
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
        let Ok(dir) = osint_cli::private_dir("macsploit-socialscan-") else {
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
                "socialscan is not installed. Install it (pip install socialscan) and refresh providers.",
            )
        })?;
        let dir = osint_cli::private_dir("macsploit-socialscan-")?;
        let report = dir.path().join("results.json");
        let args = Self::arguments(&subject, &report.to_string_lossy());
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
        let artifacts = osint_cli::capture_file(REPORT_ARTIFACT, &report, REPORT_CAP)
            .into_iter()
            .collect();
        let mut command = vec![executable.to_string_lossy().into_owned()];
        command.extend(Self::arguments(&subject, "<private-run-dir>/results.json"));
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
            "socialscan did not write its JSON report.",
        )?;
        let report: Value = serde_json::from_slice(bytes).map_err(|_| {
            CoreError::new("ProviderFailure", "socialscan JSON output is malformed.")
        })?;
        let groups = report.as_object().ok_or_else(|| {
            CoreError::new(
                "ProviderFailure",
                "socialscan JSON output is not a platform/query-keyed object.",
            )
        })?;
        // Flatten the per-group lists into one bounded record stream.
        let records: Vec<&Value> = groups
            .values()
            .filter_map(Value::as_array)
            .flatten()
            .collect();
        let mut stats = ParseStats {
            dropped_over_limit: records.len().saturating_sub(osint::MAX_RECORDS),
            ..ParseStats::default()
        };
        let mut checks = Vec::new();
        for record in records.into_iter().take(osint::MAX_RECORDS) {
            if let Some(query) = Self::record_query(record) {
                if !query.trim().is_empty() && !query.trim().eq_ignore_ascii_case(&subject.query) {
                    stats.mismatched_subject += 1;
                    continue;
                }
            }
            match Self::check(record) {
                Some(check) => checks.push(check),
                None => stats.malformed += 1,
            }
        }
        Ok(osint::build_output("socialscan", &subject, checks, stats))
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
            command: vec!["socialscan".into()],
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
        let m = SocialscanProvider.metadata();
        assert_eq!(m.id, "socialscan");
        assert_eq!(m.capabilities, vec![Capability::UsernameOsint]);
        assert_eq!(m.supported_target_types, vec![TargetType::Username]);
        assert_eq!(
            SocialscanProvider
                .setup()
                .unwrap()
                .install_command
                .as_deref(),
            Some("pip install socialscan")
        );
    }

    #[test]
    fn arguments_request_urls_and_never_filter_to_available_only() {
        let args = SocialscanProvider::arguments(&subject("@octo"), "/r.json");
        assert_eq!(args[0], "octo");
        assert!(args.contains(&"--show-urls".to_owned()));
        for forbidden in [
            "--available-only",
            "-a",
            "--proxy-list",
            "--cache-tokens",
            "--input",
            "-i",
        ] {
            assert!(!args.iter().any(|a| a == forbidden), "{forbidden}");
        }
    }

    #[test]
    fn taken_available_invalid_and_error_map_correctly() {
        let json = r#"{
          "GitHub": [{"query":"octo","platform":"GitHub","available":false,"valid":true,"success":true,"message":"Taken","link":"https://github.com/octo"}],
          "Instagram": [{"query":"octo","platform":"Instagram","available":true,"valid":true,"success":true,"message":"Available"}],
          "Twitter": [{"query":"octo","platform":"Twitter","available":false,"valid":false,"success":true,"message":"Invalid username"}],
          "Reddit": [{"query":"octo","platform":"Reddit","available":null,"valid":true,"success":false,"message":"Rate limited"}]
        }"#;
        let out = SocialscanProvider
            .parse_outcome(&exec("@octo", Some(json)))
            .unwrap();
        assert!(out.partial, "error + unknown => partial");
        let s = out.summary.clone().unwrap();
        assert_eq!(s["counts"]["positive"], 1);
        assert_eq!(s["counts"]["negative"], 1);
        assert_eq!(s["counts"]["unknown"], 1);
        assert_eq!(s["counts"]["error"], 1);
        let account = out
            .discoveries
            .iter()
            .find(|d| d.value == "github:octo")
            .unwrap();
        assert_eq!(account.asset_type, AssetType::Account);
        assert_eq!(account.relationship, Some(RelationshipType::HasAccount));
        let obs = account.observation.as_ref().unwrap();
        assert_eq!(obs.metadata["provider"], "socialscan");
        assert_eq!(obs.metadata["upstream_status"], "taken");
        assert!(out
            .discoveries
            .iter()
            .any(|d| d.asset_type == AssetType::URL && d.value == "https://github.com/octo"));
    }

    #[test]
    fn all_available_yields_only_the_subject() {
        let json = r#"{"GitHub":[{"query":"ghost","platform":"GitHub","available":true,"valid":true,"success":true,"message":"Available"}]}"#;
        let out = SocialscanProvider
            .parse_outcome(&exec("@ghost", Some(json)))
            .unwrap();
        assert!(!out.partial);
        assert_eq!(out.discoveries.len(), 1);
        assert_eq!(out.discoveries[0].asset_type, AssetType::Username);
        assert_eq!(out.summary.unwrap()["counts"]["negative"], 1);
    }

    #[test]
    fn mismatched_query_is_not_attributed() {
        let json = r#"{"GitHub":[{"query":"someone-else","platform":"GitHub","available":false,"valid":true,"success":true}]}"#;
        let out = SocialscanProvider
            .parse_outcome(&exec("@octo", Some(json)))
            .unwrap();
        assert_eq!(out.summary.unwrap()["records_mismatched_subject"], 1);
        assert!(!out
            .discoveries
            .iter()
            .any(|d| d.asset_type == AssetType::Account));
    }

    #[test]
    fn malformed_and_missing_reports_are_errors() {
        assert_eq!(
            SocialscanProvider
                .parse_outcome(&exec("@octo", Some("not json")))
                .unwrap_err()
                .code,
            "ProviderFailure"
        );
        assert_eq!(
            SocialscanProvider
                .parse_outcome(&exec("@octo", Some("[1,2]")))
                .unwrap_err()
                .code,
            "ProviderFailure"
        );
        assert_eq!(
            SocialscanProvider
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
            .insert(SOCIALSCAN_TOOL.into(), "/nonexistent/socialscan".into());
        assert_eq!(
            SocialscanProvider.installation(&tools),
            Installation::Missing
        );
    }
}
