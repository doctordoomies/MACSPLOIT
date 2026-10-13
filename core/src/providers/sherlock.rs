//! Sherlock (sherlock-project/sherlock, MIT) — Username OSINT provider.
//!
//! Verified against the upstream `sherlock_project` CLI. Behavior this integration
//! depends on (all from upstream source):
//!
//! * Executable: the `sherlock` console script (`pipx install sherlock-project`).
//! * Version: `sherlock --version` prints `sherlock v<X.Y.Z>` and exits before any
//!   network activity.
//! * Subject: a single positional username. We pass it after `--` so it can never be
//!   read as an option, and the subject is strictly validated regardless.
//! * Structured output: `--csv` writes `<username>.csv` in the working directory with
//!   the header `username,name,url_main,url_user,exists,http_status,response_time_s`.
//!   The `exists` column is the per-site status (`Claimed`/`Available`/`Unknown`/
//!   `Illegal`/`WAF`). There is no JSON output, so CSV is the machine-readable
//!   contract. The file is written when the scan finishes; a cancelled/timed-out run
//!   has none (its stdout/stderr are still kept as evidence).
//! * `--local` forces the bundled site list (no remote manifest). NSFW sites are
//!   excluded unless `--nsfw` (never passed). Sherlock has no recursion, proxy, or
//!   update behavior to disable.

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
use serde_json::Map;
use std::{
    path::PathBuf,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

pub struct SherlockProvider;

pub const SHERLOCK_TOOL: &str = "sherlock";
pub const REPORT_ARTIFACT: &str = "sherlock_csv";
/// Bounded per-site request timeout passed upstream (seconds; upstream default 60).
pub const REQUEST_TIMEOUT_SECS: u32 = 10;
/// Wall-clock limit for one run (several hundred bundled sites, each time-bounded).
pub const RUN_TIMEOUT: Duration = Duration::from_secs(600);
/// Upstream versions whose CLI/CSV schema were verified (0.x series).
pub const SUPPORTED_SERIES: &str = "0.";

impl SherlockProvider {
    /// The exact, bounded argument array. The CSV is written as `<query>.csv` in the
    /// working directory; `--` guarantees the username is positional.
    pub fn arguments(subject: &Subject) -> Vec<String> {
        vec![
            "--csv".into(),
            "--local".into(),
            "--no-color".into(),
            "--timeout".into(),
            REQUEST_TIMEOUT_SECS.to_string(),
            "--".into(),
            subject.query.clone(),
        ]
    }

    fn locate(tools: &ToolConfig) -> Option<PathBuf> {
        osint_cli::locate(tools, SHERLOCK_TOOL)
    }

    /// Map an upstream `exists` status to the provider-neutral status.
    fn status(label: &str) -> CheckStatus {
        match label {
            "Claimed" => CheckStatus::Positive,
            "Available" => CheckStatus::Negative,
            // A site that forbids the username (reserved) is a policy result, not a hit.
            "Illegal" => CheckStatus::Blocked,
            // Indeterminate/blocked-by-WAF checks are errors, not absence.
            "Unknown" | "WAF" => CheckStatus::Error,
            _ => CheckStatus::Unknown,
        }
    }

    /// Parse CSV content (RFC-4180-ish: double-quoted fields, `""` escape, CRLF)
    /// into records. Bounded by [`osint::MAX_RECORDS`] rows at the call site.
    fn parse_csv(content: &str) -> Vec<Vec<String>> {
        let mut rows = Vec::new();
        let mut field = String::new();
        let mut record = Vec::new();
        let mut in_quotes = false;
        let mut chars = content.chars().peekable();
        let mut saw_field = false;
        while let Some(c) = chars.next() {
            if in_quotes {
                if c == '"' {
                    if chars.peek() == Some(&'"') {
                        field.push('"');
                        chars.next();
                    } else {
                        in_quotes = false;
                    }
                } else {
                    field.push(c);
                }
                continue;
            }
            match c {
                '"' => {
                    in_quotes = true;
                    saw_field = true;
                }
                ',' => {
                    record.push(std::mem::take(&mut field));
                    saw_field = true;
                }
                '\r' => {}
                '\n' => {
                    if saw_field || !field.is_empty() || !record.is_empty() {
                        record.push(std::mem::take(&mut field));
                        rows.push(std::mem::take(&mut record));
                    }
                    saw_field = false;
                }
                _ => {
                    field.push(c);
                    saw_field = true;
                }
            }
        }
        if saw_field || !field.is_empty() || !record.is_empty() {
            record.push(field);
            rows.push(record);
        }
        rows
    }

    /// Build a normalized check from one CSV record given the column index map.
    fn check(record: &[String], columns: &Columns) -> Option<OsintCheck> {
        let get = |index: Option<usize>| index.and_then(|i| record.get(i)).map(String::as_str);
        let platform = osint::clean_text(get(columns.name)?, osint::MAX_FIELD_BYTES);
        let platform_key = osint::platform_key(&platform)?;
        let upstream_status = osint::clean_text(get(columns.exists)?, osint::MAX_KEY_BYTES);
        if upstream_status.is_empty() {
            return None;
        }
        let raw_url = get(columns.url_user).unwrap_or("").trim();
        let url = osint::safe_url(raw_url);
        Some(OsintCheck {
            status: Self::status(&upstream_status),
            platform,
            platform_key,
            category: None,
            upstream_status,
            url_rejected: !raw_url.is_empty() && url.is_none(),
            url,
            reason: None,
            profile: Map::new(),
            media: Map::new(),
            upstream_confidence: None,
        })
    }
}

/// Column indices resolved from the CSV header (order is stable upstream but we
/// resolve by name so a column addition cannot silently shift a field).
struct Columns {
    username: Option<usize>,
    name: Option<usize>,
    url_user: Option<usize>,
    exists: Option<usize>,
}

impl Columns {
    fn from_header(header: &[String]) -> Self {
        let index = |want: &str| header.iter().position(|h| h.trim() == want);
        Self {
            username: index("username"),
            name: index("name"),
            url_user: index("url_user"),
            exists: index("exists"),
        }
    }
}

impl Provider for SherlockProvider {
    fn setup(&self) -> Option<ProviderSetup> {
        Some(ProviderSetup {
            install_command: Some("pipx install sherlock-project".into()),
            homepage: Some("https://github.com/sherlock-project/sherlock".into()),
            documentation: Some("https://sherlockproject.xyz/".into()),
        })
    }

    fn metadata(&self) -> ProviderMetadata {
        ProviderMetadata {
            id: "sherlock".into(),
            name: "Sherlock".into(),
            description: "Username OSINT: checks public platforms for one explicitly selected username (one bounded scan, bundled site list, no NSFW, no recursion, no proxies).".into(),
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
        let Ok(dir) = osint_cli::private_dir("macsploit-sherlock-") else {
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
                let version = text
                    .lines()
                    .find(|line| line.to_lowercase().contains("sherlock") || line.contains('.'))
                    .and_then(process::scan_version);
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
                "Sherlock is not installed. Install it (pipx install sherlock-project) and refresh providers.",
            )
        })?;
        let dir = osint_cli::private_dir("macsploit-sherlock-")?;
        let args = Self::arguments(&subject);
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
        // Sherlock writes `<username>.csv` in the working directory.
        let report = dir.path().join(format!("{}.csv", subject.query));
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
        let subject = osint_cli::username_subject(&execution.target, execution.capability)?;
        let bytes = osint_cli::report_bytes(
            execution,
            REPORT_ARTIFACT,
            "Sherlock did not write its CSV report.",
        )?;
        let content = std::str::from_utf8(bytes)
            .map_err(|_| CoreError::new("ProviderFailure", "Sherlock CSV output is not UTF-8."))?;
        let mut rows = Self::parse_csv(content).into_iter();
        let header = rows
            .next()
            .ok_or_else(|| CoreError::new("ProviderFailure", "Sherlock CSV output is empty."))?;
        let columns = Columns::from_header(&header);
        if columns.name.is_none() || columns.exists.is_none() {
            return Err(CoreError::new(
                "ProviderFailure",
                "Sherlock CSV output is missing required columns.",
            ));
        }
        let rows: Vec<Vec<String>> = rows.collect();
        let mut stats = ParseStats {
            dropped_over_limit: rows.len().saturating_sub(osint::MAX_RECORDS),
            ..ParseStats::default()
        };
        let mut checks = Vec::new();
        for record in rows.into_iter().take(osint::MAX_RECORDS) {
            // A row about a different username (never expected from a single-subject
            // run) is not attributed to this subject.
            if let Some(identifier) = columns.username.and_then(|i| record.get(i)) {
                if !identifier.trim().is_empty()
                    && !identifier.trim().eq_ignore_ascii_case(&subject.query)
                {
                    stats.mismatched_subject += 1;
                    continue;
                }
            }
            match Self::check(&record, &columns) {
                Some(check) => checks.push(check),
                None => stats.malformed += 1,
            }
        }
        Ok(osint::build_output("sherlock", &subject, checks, stats))
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

    fn exec(target: &str, csv: Option<&str>) -> Execution {
        Execution {
            target: target.into(),
            capability: Capability::UsernameOsint,
            command: vec!["sherlock".into()],
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_status: Some(0),
            pid: None,
            timed_out: false,
            started_at: crate::now(),
            ended_at: crate::now(),
            artifacts: csv
                .map(|c| ExecutionArtifact {
                    name: REPORT_ARTIFACT.into(),
                    bytes: c.as_bytes().to_vec(),
                    observed_bytes: Some(c.len() as u64),
                    over_limit: false,
                })
                .into_iter()
                .collect(),
            cancelled: false,
        }
    }

    const HEADER: &str = "username,name,url_main,url_user,exists,http_status,response_time_s";

    #[test]
    fn metadata_is_username_osint_only() {
        let m = SherlockProvider.metadata();
        assert_eq!(m.id, "sherlock");
        assert_eq!(m.capabilities, vec![Capability::UsernameOsint]);
        assert_eq!(m.supported_target_types, vec![TargetType::Username]);
        assert_eq!(m.risk_class, RiskClass::ActiveLowImpact);
        assert_eq!(m.network_activity, NetworkActivity::Network);
        assert_eq!(
            SherlockProvider.setup().unwrap().install_command.as_deref(),
            Some("pipx install sherlock-project")
        );
    }

    #[test]
    fn arguments_are_bounded_and_positional_username_is_guarded() {
        let args = SherlockProvider::arguments(&subject("@octo"));
        assert_eq!(
            args,
            [
                "--csv",
                "--local",
                "--no-color",
                "--timeout",
                "10",
                "--",
                "octo"
            ]
        );
        for forbidden in ["--nsfw", "--proxy", "--tor"] {
            assert!(!args.iter().any(|a| a == forbidden));
        }
    }

    #[test]
    fn non_username_capability_is_rejected() {
        assert!(osint_cli::username_subject("@octo", Capability::EmailOsint).is_err());
        assert!(osint_cli::username_subject("@octo", Capability::WebCrawling).is_err());
    }

    #[test]
    fn parses_claimed_available_illegal_waf_unknown() {
        let csv = format!(
            "{HEADER}\n\
             octo,GitHub,https://github.com,https://github.com/octo,Claimed,200,0.4\n\
             octo,GitLab,https://gitlab.com,https://gitlab.com/octo,Available,404,0.3\n\
             octo,Reddit,https://reddit.com,https://reddit.com/u/octo,WAF,403,0.5\n\
             octo,SomeSite,https://some.test,https://some.test/octo,Illegal,,0.0\n\
             octo,Weird,https://weird.test,,Mystery,000,0.1\n"
        );
        let out = SherlockProvider
            .parse_outcome(&exec("@octo", Some(&csv)))
            .unwrap();
        assert!(out.partial, "WAF (error) + Mystery (unknown) => partial");
        let s = out.summary.clone().unwrap();
        assert_eq!(s["counts"]["positive"], 1);
        assert_eq!(s["counts"]["negative"], 1);
        assert_eq!(s["counts"]["error"], 1);
        assert_eq!(s["counts"]["blocked"], 1);
        assert_eq!(s["counts"]["unknown"], 1);
        let d = &out.discoveries;
        assert_eq!(d[0].asset_type, AssetType::Username);
        assert_eq!(d[1].asset_type, AssetType::Account);
        assert_eq!(d[1].value, "github:octo");
        assert_eq!(d[1].relationship, Some(RelationshipType::HasAccount));
        let obs = d[1].observation.as_ref().unwrap();
        assert_eq!(obs.metadata["provider"], "sherlock");
        assert_eq!(obs.metadata["upstream_status"], "Claimed");
        assert_eq!(d[2].asset_type, AssetType::URL);
        assert_eq!(d[2].value, "https://github.com/octo");
        assert_eq!(d[2].relationship, Some(RelationshipType::ProfileUrl));
    }

    #[test]
    fn zero_results_yield_only_the_subject() {
        let csv = format!("{HEADER}\n");
        let out = SherlockProvider
            .parse_outcome(&exec("@ghost", Some(&csv)))
            .unwrap();
        assert!(!out.partial);
        assert_eq!(out.discoveries.len(), 1);
        assert_eq!(out.discoveries[0].asset_type, AssetType::Username);
        assert_eq!(out.summary.unwrap()["counts"]["positive"], 0);
    }

    #[test]
    fn quoted_fields_with_commas_parse_correctly() {
        let csv = format!(
            "{HEADER}\n\
             octo,\"X, formerly Twitter\",https://x.com,https://x.com/octo,Claimed,200,0.2\n"
        );
        let out = SherlockProvider
            .parse_outcome(&exec("@octo", Some(&csv)))
            .unwrap();
        let account = out
            .discoveries
            .iter()
            .find(|d| d.asset_type == AssetType::Account)
            .unwrap();
        assert_eq!(
            account.observation.as_ref().unwrap().metadata["platform"],
            "X, formerly Twitter"
        );
    }

    #[test]
    fn malformed_and_missing_reports_are_errors() {
        assert_eq!(
            SherlockProvider
                .parse_outcome(&exec("@octo", None))
                .unwrap_err()
                .code,
            "ProviderFailure"
        );
        // Header without required columns.
        assert_eq!(
            SherlockProvider
                .parse_outcome(&exec("@octo", Some("a,b,c\n1,2,3\n")))
                .unwrap_err()
                .code,
            "ProviderFailure"
        );
        let mut over = exec("@octo", Some(HEADER));
        over.artifacts[0].over_limit = true;
        assert_eq!(
            SherlockProvider.parse_outcome(&over).unwrap_err().code,
            "BudgetExceeded"
        );
    }

    #[test]
    fn mismatched_username_rows_are_counted_not_attributed() {
        let csv = format!(
            "{HEADER}\n\
             someone-else,GitHub,https://github.com,https://github.com/else,Claimed,200,0.4\n"
        );
        let out = SherlockProvider
            .parse_outcome(&exec("@octo", Some(&csv)))
            .unwrap();
        assert_eq!(out.summary.unwrap()["records_mismatched_subject"], 1);
        assert!(!out
            .discoveries
            .iter()
            .any(|d| d.asset_type == AssetType::Account));
    }

    #[test]
    fn missing_executable_reports_missing() {
        let mut tools = ToolConfig::default();
        tools
            .overrides
            .insert(SHERLOCK_TOOL.into(), "/nonexistent/sherlock".into());
        assert_eq!(SherlockProvider.installation(&tools), Installation::Missing);
    }
}
