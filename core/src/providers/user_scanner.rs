//! user-scanner (kaifcodec/user-scanner, MIT) — Username + Email OSINT provider.
//!
//! Verified against the upstream source of user-scanner 1.5.0, 1.5.1.3, 1.5.2, and
//! 1.5.2.1 (PyPI sdists); fixtures model the 1.5.2.1 JSON schema. Supported: 1.5.x.
//!
//! Upstream behavior this integration depends on (all verified in source):
//!
//! * Executable: the `user-scanner` console script (`pipx install user-scanner`).
//! * Version: `user-scanner --version` prints `user-scanner current version -> X`
//!   from the bundled version.json and exits before any network activity.
//! * Subject: `--username=<handle>` / `--email=<address>` (the `=` form keeps a value
//!   from ever being parsed as an option; subjects are also validated strictly).
//! * Structured output: `--format json --output <file>` writes a JSON **array** of
//!   every module result (`status`, `reason`, `username`|`email`, `site_name`,
//!   `category`, `url`, `extra`, `media`) **only when the scan finishes**. If the file
//!   already exists upstream appends to it, so every run uses a fresh private dir.
//!   A cancelled or timed-out run therefore has no structured results; its
//!   stdout/stderr are still preserved as evidence.
//! * Defaults that matter: an automatic PyPI update check with an interactive
//!   prompt is ON unless the config file at `USER_SCANNER_CONFIG` disables it, so
//!   every run gets a private config with `auto_update_status=false`. Loud modules
//!   (ones that can notify the subject, e.g. password-reset flows) are skipped
//!   unless `--allow-loud`; never passed. NSFW modules are included unless
//!   `--no-nsfw`; always passed. Username input is expanded as a pattern
//!   (`[a-z]{2}` …); subjects can never contain pattern characters and `--stop 1`
//!   caps expansion anyway. Default concurrency is 60 (username) / 25 (email); this
//!   integration lowers it. Per-module request timeout defaults to 15 s.
//! * Never passed: `--cross-scan` (recursive pivots), `--hudson` (breach /
//!   infostealer intelligence), `--proxy-file`/`--validate-proxies` (proxy
//!   rotation), `--allow-loud`, `--email-domains`, `--update`, file inputs.

use super::{
    Capability, Execution, ExecutionArtifact, ParsedOutput, Provider, ProviderContext,
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
    io::Read,
    path::Path,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

pub struct UserScannerProvider;

pub const USER_SCANNER_TOOL: &str = "user-scanner";
/// The artifact name of the captured JSON report.
pub const REPORT_ARTIFACT: &str = "user_scanner_json";
const STDOUT_CAP: usize = 256 * 1024;
const STDERR_CAP: usize = 64 * 1024;
/// The JSON report becomes its own evidence record, which is capped at 1 MiB.
pub const REPORT_CAP: u64 = 1024 * 1024;
/// Bounded per-module request timeout passed upstream (seconds).
pub const REQUEST_TIMEOUT_SECS: u32 = 10;
/// Bounded upstream concurrency (default upstream: 60 username / 25 email).
pub const USERNAME_CONCURRENCY: u32 = 20;
pub const EMAIL_CONCURRENCY: u32 = 8;
/// Wall-clock limit for one run. A full catalog scan is ~2,400 username modules or
/// ~200 email modules; upstream bounds each module at its request timeout + 10 s.
pub const RUN_TIMEOUT: Duration = Duration::from_secs(900);
/// Upstream versions whose CLI/defaults/JSON schema were verified.
pub const SUPPORTED_SERIES: &str = "1.5.";

/// Private per-run upstream configuration: no PyPI update check/prompt; keep the
/// loud-module prompt enabled so a non-interactive run skips loud modules.
const PRIVATE_CONFIG: &str = r#"{"auto_update_status": false, "auto_hudson_prompt": true, "auto_loud_single_module_prompt": true}"#;

impl UserScannerProvider {
    /// The exact, bounded argument array. `output` is the report path.
    pub fn arguments(capability: Capability, subject: &Subject, output: &str) -> Vec<String> {
        let (subject_arg, concurrency) = match capability {
            Capability::EmailOsint => (format!("--email={}", subject.query), EMAIL_CONCURRENCY),
            _ => (
                format!("--username={}", subject.query),
                USERNAME_CONCURRENCY,
            ),
        };
        vec![
            subject_arg,
            "--no-nsfw".into(),
            "--stop".into(),
            "1".into(),
            "--concurrency".into(),
            concurrency.to_string(),
            "--timeout".into(),
            REQUEST_TIMEOUT_SECS.to_string(),
            "--format".into(),
            "json".into(),
            "--output".into(),
            output.into(),
        ]
    }

    fn subject_for(target: &str, capability: Capability) -> Result<Subject> {
        let kind = match capability {
            Capability::UsernameOsint => TargetType::Username,
            Capability::EmailOsint => TargetType::EmailAddress,
            _ => {
                return Err(CoreError::new(
                    "ProviderUnsupported",
                    "user-scanner only provides username and email OSINT.",
                ))
            }
        };
        Subject::from_target(kind, target)
    }

    /// Environment for every upstream invocation: private config, no colors.
    fn environment(config: &Path) -> Vec<(String, String)> {
        vec![
            (
                "USER_SCANNER_CONFIG".into(),
                config.to_string_lossy().into_owned(),
            ),
            ("NO_COLOR".into(), "1".into()),
            ("TERM".into(), "dumb".into()),
            ("PYTHONIOENCODING".into(), "utf-8".into()),
            ("PYTHONDONTWRITEBYTECODE".into(), "1".into()),
        ]
    }

    fn private_run_dir() -> Result<tempfile::TempDir> {
        let dir = tempfile::Builder::new()
            .prefix("macsploit-user-scanner-")
            .tempdir()?;
        std::fs::write(dir.path().join("config.json"), PRIVATE_CONFIG)?;
        Ok(dir)
    }

    /// Read the report without following a symlink and without exceeding the bound.
    fn capture_report(path: &Path) -> Option<ExecutionArtifact> {
        let metadata = std::fs::symlink_metadata(path).ok()?;
        if !metadata.file_type().is_file() {
            return Some(ExecutionArtifact {
                name: REPORT_ARTIFACT.into(),
                bytes: Vec::new(),
                observed_bytes: None,
                over_limit: true,
            });
        }
        let observed = metadata.len();
        if observed > REPORT_CAP {
            return Some(ExecutionArtifact {
                name: REPORT_ARTIFACT.into(),
                bytes: Vec::new(),
                observed_bytes: Some(observed),
                over_limit: true,
            });
        }
        let mut bytes = Vec::new();
        let file = std::fs::File::open(path).ok()?;
        file.take(REPORT_CAP + 1).read_to_end(&mut bytes).ok()?;
        let over_limit = bytes.len() as u64 > REPORT_CAP;
        if over_limit {
            bytes.clear();
        }
        Some(ExecutionArtifact {
            name: REPORT_ARTIFACT.into(),
            bytes,
            observed_bytes: Some(observed),
            over_limit,
        })
    }

    fn status(label: &str) -> CheckStatus {
        match label {
            "Found" | "Registered" => CheckStatus::Positive,
            "Not Found" | "Not Registered" => CheckStatus::Negative,
            "Skipped" => CheckStatus::Blocked,
            "Error" => CheckStatus::Error,
            _ => CheckStatus::Unknown,
        }
    }

    /// Normalize one untrusted upstream record. `None` means malformed.
    fn check(record: &Value) -> Option<OsintCheck> {
        let record = record.as_object()?;
        let platform =
            osint::clean_text(record.get("site_name")?.as_str()?, osint::MAX_FIELD_BYTES);
        let platform_key = osint::platform_key(&platform)?;
        let upstream_status =
            osint::clean_text(record.get("status")?.as_str()?, osint::MAX_KEY_BYTES);
        if upstream_status.is_empty() {
            return None;
        }
        let text = |key: &str| {
            record
                .get(key)
                .and_then(Value::as_str)
                .map(|v| osint::clean_text(v, osint::MAX_FIELD_BYTES))
                .filter(|v| !v.is_empty())
        };
        let raw_url = record.get("url").and_then(Value::as_str).unwrap_or("");
        let url = osint::safe_url(raw_url);
        let empty = Map::new();
        let extra = record
            .get("extra")
            .and_then(Value::as_object)
            .unwrap_or(&empty);
        // Cross-scan bookkeeping keys are upstream annotations, not profile facts.
        let upstream_confidence = extra
            .get("confidence")
            .and_then(Value::as_str)
            .map(|v| osint::clean_text(v, osint::MAX_KEY_BYTES))
            .filter(|v| !v.is_empty());
        let mut profile_source = extra.clone();
        profile_source.remove("confidence");
        profile_source.remove("pivot_source");
        Some(OsintCheck {
            status: Self::status(&upstream_status),
            platform,
            platform_key,
            category: text("category"),
            upstream_status,
            url_rejected: !raw_url.trim().is_empty() && url.is_none(),
            url,
            reason: text("reason"),
            profile: osint::bounded_profile(&profile_source),
            media: osint::bounded_media(
                record
                    .get("media")
                    .and_then(Value::as_object)
                    .unwrap_or(&empty),
            ),
            upstream_confidence,
        })
    }

    fn report(execution: &Execution) -> Result<&[u8]> {
        let artifact = execution
            .artifacts
            .iter()
            .find(|a| a.name == REPORT_ARTIFACT)
            .ok_or_else(|| {
                CoreError::new(
                    "ProviderFailure",
                    "user-scanner did not write its JSON report.",
                )
            })?;
        if artifact.over_limit {
            return Err(CoreError::new(
                "BudgetExceeded",
                "The user-scanner JSON report exceeded the 1 MiB bound; raw output is preserved as evidence.",
            ));
        }
        Ok(&artifact.bytes)
    }
}

impl Provider for UserScannerProvider {
    fn setup(&self) -> Option<ProviderSetup> {
        Some(ProviderSetup {
            install_command: Some("pipx install user-scanner".into()),
            homepage: Some("https://github.com/kaifcodec/user-scanner".into()),
            documentation: Some("https://pypi.org/project/user-scanner/".into()),
        })
    }

    fn metadata(&self) -> ProviderMetadata {
        ProviderMetadata {
            id: "user_scanner".into(),
            name: "user-scanner".into(),
            description: "Username + Email OSINT: checks public platforms for an explicitly selected username or email (one bounded scan, no recursion, no breach data, no proxies).".into(),
            version: "external".into(),
            capabilities: vec![Capability::UsernameOsint, Capability::EmailOsint],
            supported_target_types: vec![TargetType::Username, TargetType::EmailAddress],
            // Ordinary requests to third-party public platforms; never to subject-owned
            // infrastructure, and loud (subject-notifying) modules are skipped.
            risk_class: RiskClass::ActiveLowImpact,
            offline: false,
        }
    }

    fn installation(&self, tools: &ToolConfig) -> Installation {
        let Some(executable) = tools.locate(USER_SCANNER_TOOL) else {
            return Installation::Missing;
        };
        let Ok(dir) = Self::private_run_dir() else {
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
                env: Self::environment(&dir.path().join("config.json")),
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
                    .find(|line| line.contains("version"))
                    .and_then(process::scan_version)
                    .unwrap_or_else(|| "unknown".into());
                if version.starts_with(SUPPORTED_SERIES) {
                    Installation::Installed {
                        version,
                        path: Some(executable),
                    }
                } else {
                    Installation::UnsupportedVersion { version }
                }
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
        // Re-validate in the provider — the core is the security boundary.
        let subject = Self::subject_for(target, capability)?;
        let executable = ctx.tools.locate(USER_SCANNER_TOOL).ok_or_else(|| {
            CoreError::new(
                "ProviderMissing",
                "user-scanner is not installed. Install it (pipx install user-scanner) and refresh providers.",
            )
        })?;
        let dir = Self::private_run_dir()?;
        let report = dir.path().join("results.json");
        let args = Self::arguments(capability, &subject, &report.to_string_lossy());
        let outcome = process::run_with(
            &executable,
            &args,
            ctx.cancelled,
            ctx.deadline,
            STDOUT_CAP,
            STDERR_CAP,
            &RunOptions {
                env: Self::environment(&dir.path().join("config.json")),
                current_dir: Some(dir.path().to_path_buf()),
            },
        )?;
        let artifacts = Self::capture_report(&report).into_iter().collect();
        // The persisted command keeps the exact argv except the private temporary
        // report path, which is replaced by a stable placeholder.
        let mut command = vec![executable.to_string_lossy().into_owned()];
        command.extend(Self::arguments(
            capability,
            &subject,
            "<private-run-dir>/results.json",
        ));
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
        let subject = Self::subject_for(&execution.target, execution.capability)?;
        let report: Value = serde_json::from_slice(Self::report(execution)?).map_err(|_| {
            CoreError::new("ProviderFailure", "user-scanner JSON output is malformed.")
        })?;
        let records = report.as_array().ok_or_else(|| {
            CoreError::new(
                "ProviderFailure",
                "user-scanner JSON output is not a result array.",
            )
        })?;
        let mut stats = ParseStats {
            dropped_over_limit: records.len().saturating_sub(osint::MAX_RECORDS),
            ..ParseStats::default()
        };
        let identifier_key = match subject.kind {
            osint::SubjectKind::Email => "email",
            osint::SubjectKind::Username => "username",
        };
        let mut checks = Vec::new();
        for record in records.iter().take(osint::MAX_RECORDS) {
            // A record about a different identifier (e.g. upstream expansion) is never
            // attributed to this subject.
            if let Some(identifier) = record.get(identifier_key).and_then(Value::as_str) {
                if !identifier.eq_ignore_ascii_case(&subject.query) {
                    stats.mismatched_subject += 1;
                    continue;
                }
            }
            match Self::check(record) {
                Some(check) => checks.push(check),
                None => stats.malformed += 1,
            }
        }
        Ok(osint::build_output("user_scanner", &subject, checks, stats))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assets::{AssetType, RelationshipType};

    fn subject(kind: TargetType, value: &str) -> Subject {
        Subject::from_target(kind, value).unwrap()
    }

    fn exec(capability: Capability, target: &str, report: Option<&str>) -> Execution {
        Execution {
            target: target.into(),
            capability,
            command: vec!["user-scanner".into()],
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_status: Some(0),
            pid: None,
            timed_out: false,
            started_at: crate::now(),
            ended_at: crate::now(),
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
    fn metadata_capabilities_and_targets() {
        let m = UserScannerProvider.metadata();
        assert_eq!(m.id, "user_scanner");
        assert_eq!(
            m.capabilities,
            vec![Capability::UsernameOsint, Capability::EmailOsint]
        );
        assert_eq!(
            m.supported_target_types,
            vec![TargetType::Username, TargetType::EmailAddress]
        );
        assert_eq!(m.risk_class, RiskClass::ActiveLowImpact);
        assert!(!m.offline);
        assert!(Capability::UsernameOsint.is_osint() && !Capability::WebCrawling.is_osint());
        let setup = UserScannerProvider.setup().unwrap();
        assert_eq!(
            setup.install_command.as_deref(),
            Some("pipx install user-scanner")
        );
    }

    #[test]
    fn arguments_are_bounded_and_never_enable_prohibited_modes() {
        let user = subject(TargetType::Username, "@octo");
        let args = UserScannerProvider::arguments(Capability::UsernameOsint, &user, "/r.json");
        assert_eq!(
            args,
            [
                "--username=octo",
                "--no-nsfw",
                "--stop",
                "1",
                "--concurrency",
                "20",
                "--timeout",
                "10",
                "--format",
                "json",
                "--output",
                "/r.json"
            ]
        );
        let email = subject(TargetType::EmailAddress, "a@example.test");
        let args = UserScannerProvider::arguments(Capability::EmailOsint, &email, "/r.json");
        assert_eq!(args[0], "--email=a@example.test");
        assert!(args.contains(&"8".to_owned()));
        for args in [
            UserScannerProvider::arguments(Capability::UsernameOsint, &user, "/r"),
            UserScannerProvider::arguments(Capability::EmailOsint, &email, "/r"),
        ] {
            for forbidden in [
                "--cross-scan",
                "--hudson",
                "--hudson-scan",
                "--proxy-file",
                "-P",
                "--validate-proxies",
                "--allow-loud",
                "--email-domains",
                "--update",
                "-U",
                "--all",
                "-uf",
                "-ef",
            ] {
                assert!(
                    !args
                        .iter()
                        .any(|a| a == forbidden || a.starts_with(&format!("{forbidden}="))),
                    "{forbidden} must never be passed"
                );
            }
        }
    }

    #[test]
    fn option_injection_and_pattern_subjects_are_rejected() {
        for bad in ["@-rf", "@--hudson", "@a[0-9]{3}", "@a\\b", "@..", "@a b"] {
            assert!(
                UserScannerProvider::subject_for(bad, Capability::UsernameOsint).is_err(),
                "{bad}"
            );
        }
        assert!(
            UserScannerProvider::subject_for("-x@example.test", Capability::EmailOsint).is_err()
        );
        assert!(
            UserScannerProvider::subject_for("@octo", Capability::WebCrawling).is_err(),
            "non-OSINT capability"
        );
    }

    #[test]
    fn parses_positive_negative_blocked_error_unknown() {
        let report = r#"[
          {"status":"Found","reason":"","username":"octo","site_name":"Github","category":"Dev","url":"https://github.com/octo","extra":{"name":"Octo Cat","followers":12,"nested":{"x":1}},"media":{"avatar":"https://avatars.example.test/o.png","bad":"javascript:alert(1)"}},
          {"status":"Not Found","reason":"","username":"octo","site_name":"Gitlab","category":"Dev","url":"https://gitlab.com/octo","extra":{},"media":{}},
          {"status":"Error","reason":"ConnectError: Connection timed out","username":"octo","site_name":"Reddit","category":"Social","url":"","extra":{},"media":{}},
          {"status":"Skipped","reason":"Notifies the target by forgot password email or similar","username":"octo","site_name":"Leetcode","category":"Dev","url":"","extra":{},"media":{}},
          {"status":"Mystery","reason":"","username":"octo","site_name":"Odd","category":"Other","url":"","extra":{},"media":{}}
        ]"#;
        let out = UserScannerProvider
            .parse_outcome(&exec(Capability::UsernameOsint, "@octo", Some(report)))
            .unwrap();
        assert!(out.partial, "error/unknown make the run partial");
        let summary = out.summary.unwrap();
        assert_eq!(summary["counts"]["positive"], 1);
        assert_eq!(summary["counts"]["negative"], 1);
        assert_eq!(summary["counts"]["blocked"], 1);
        assert_eq!(summary["counts"]["error"], 1);
        assert_eq!(summary["counts"]["unknown"], 1);
        assert_eq!(summary["errors"][0]["platform"], "Reddit");
        // Subject + Account + profile URL.
        let d = &out.discoveries;
        assert_eq!(d.len(), 3);
        assert_eq!(
            (d[0].asset_type, d[0].value.as_str()),
            (AssetType::Username, "@octo")
        );
        assert_eq!(d[1].asset_type, AssetType::Account);
        assert_eq!(d[1].value, "github:octo");
        assert_eq!(d[1].relationship, Some(RelationshipType::HasAccount));
        let obs = d[1].observation.as_ref().unwrap();
        assert_eq!(obs.confidence, "REPORTED");
        assert_eq!(obs.metadata["upstream_status"], "Found");
        assert_eq!(obs.metadata["profile"]["name"], "Octo Cat");
        assert_eq!(obs.metadata["profile"]["followers"], 12);
        assert!(obs.metadata["profile"].get("nested").is_none());
        assert!(obs.metadata["media"].get("bad").is_none());
        assert_eq!(
            (d[2].asset_type, d[2].value.as_str()),
            (AssetType::URL, "https://github.com/octo")
        );
        assert_eq!(d[2].relationship, Some(RelationshipType::ProfileUrl));
        assert_eq!(d[2].source.as_deref(), Some("github:octo"));
    }

    #[test]
    fn email_registration_without_url_is_an_account() {
        let report = r#"[{"status":"Registered","reason":"","email":"a@example.test","site_name":"Amazon","category":"Shopping","url":"","extra":{},"media":{}},
                         {"status":"Not Registered","reason":"","email":"a@example.test","site_name":"Spotify","category":"Music","url":"","extra":{},"media":{}}]"#;
        let out = UserScannerProvider
            .parse_outcome(&exec(
                Capability::EmailOsint,
                "a@example.test",
                Some(report),
            ))
            .unwrap();
        assert!(!out.partial);
        assert_eq!(out.discoveries.len(), 2);
        assert_eq!(out.discoveries[0].asset_type, AssetType::EmailAddress);
        assert_eq!(out.discoveries[1].value, "amazon:a@example.test");
    }

    #[test]
    fn duplicates_oversized_fields_invalid_urls_and_mismatches_are_bounded() {
        let long = "x".repeat(10_000);
        let report = serde_json::json!([
            {"status":"Found","username":"octo","site_name":"Github","url":"https://github.com/octo","extra":{"bio": long},"media":{}},
            {"status":"Found","username":"octo","site_name":"Github","url":"https://github.com/octo","extra":{},"media":{}},
            {"status":"Found","username":"octo","site_name":"Evil","url":"javascript:alert(1)","extra":{},"media":{}},
            {"status":"Found","username":"someone-else","site_name":"Other","url":"https://other.example.test/x","extra":{},"media":{}},
            {"status":"Found","username":"octo","site_name": long,"url":"","extra":{},"media":{}},
            "not an object",
            {"site_name":"NoStatus"}
        ])
        .to_string();
        let out = UserScannerProvider
            .parse_outcome(&exec(Capability::UsernameOsint, "@octo", Some(&report)))
            .unwrap();
        let s = out.summary.unwrap();
        assert_eq!(s["duplicates"], 1);
        assert_eq!(s["urls_rejected"], 1);
        assert_eq!(s["records_mismatched_subject"], 1);
        assert_eq!(s["records_malformed"], 2);
        assert!(out.partial);
        // No URL asset for the javascript: URL; bio bounded.
        assert!(!out
            .discoveries
            .iter()
            .any(|d| d.value.starts_with("javascript")));
        let github = out
            .discoveries
            .iter()
            .find(|d| d.value == "github:octo")
            .unwrap();
        let bio = github.observation.as_ref().unwrap().metadata["profile"]["bio"]
            .as_str()
            .unwrap();
        assert!(bio.len() <= osint::MAX_FIELD_BYTES);
        for d in &out.discoveries {
            assert!(d.value.len() <= osint::MAX_URL_BYTES);
        }
    }

    #[test]
    fn malformed_missing_and_oversized_reports_are_errors() {
        let user = Capability::UsernameOsint;
        assert_eq!(
            UserScannerProvider
                .parse_outcome(&exec(user, "@octo", Some("{not json")))
                .unwrap_err()
                .code,
            "ProviderFailure"
        );
        assert_eq!(
            UserScannerProvider
                .parse_outcome(&exec(user, "@octo", Some(r#"{"a":1}"#)))
                .unwrap_err()
                .code,
            "ProviderFailure"
        );
        assert_eq!(
            UserScannerProvider
                .parse_outcome(&exec(user, "@octo", None))
                .unwrap_err()
                .code,
            "ProviderFailure"
        );
        let mut over = exec(user, "@octo", Some("[]"));
        over.artifacts[0].over_limit = true;
        assert_eq!(
            UserScannerProvider.parse_outcome(&over).unwrap_err().code,
            "BudgetExceeded"
        );
    }

    #[test]
    fn record_count_is_bounded() {
        let mut records = Vec::new();
        for i in 0..(osint::MAX_RECORDS + 3) {
            records.push(serde_json::json!({"status":"Not Found","username":"octo","site_name":format!("S{i}")}));
        }
        let report = Value::Array(records).to_string();
        let out = UserScannerProvider
            .parse_outcome(&exec(Capability::UsernameOsint, "@octo", Some(&report)))
            .unwrap();
        let s = out.summary.unwrap();
        assert_eq!(s["records_dropped_over_limit"], 3);
        assert_eq!(s["counts"]["negative"], osint::MAX_RECORDS);
        assert!(out.partial);
    }

    #[test]
    fn positive_results_are_capped() {
        let mut records = Vec::new();
        for i in 0..(osint::MAX_POSITIVE + 5) {
            records.push(serde_json::json!({"status":"Found","username":"octo","site_name":format!("Site{i}")}));
        }
        let report = Value::Array(records).to_string();
        let out = UserScannerProvider
            .parse_outcome(&exec(Capability::UsernameOsint, "@octo", Some(&report)))
            .unwrap();
        let accounts = out
            .discoveries
            .iter()
            .filter(|d| d.asset_type == AssetType::Account)
            .count();
        assert_eq!(accounts, osint::MAX_POSITIVE);
        assert_eq!(out.summary.unwrap()["positive_over_limit"], 5);
    }

    #[test]
    fn missing_executable_reports_missing() {
        let mut tools = ToolConfig::default();
        tools
            .overrides
            .insert(USER_SCANNER_TOOL.into(), "/nonexistent/user-scanner".into());
        assert_eq!(
            UserScannerProvider.installation(&tools),
            Installation::Missing
        );
    }

    #[test]
    fn capture_report_rejects_symlinks_and_oversized_files() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.json");
        std::fs::write(&real, "[]").unwrap();
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(
            UserScannerProvider::capture_report(&link)
                .unwrap()
                .over_limit
        );
        let ok = UserScannerProvider::capture_report(&real).unwrap();
        assert_eq!((ok.bytes.as_slice(), ok.over_limit), (&b"[]"[..], false));
        let big = dir.path().join("big.json");
        std::fs::write(&big, vec![b' '; (REPORT_CAP + 1) as usize]).unwrap();
        let captured = UserScannerProvider::capture_report(&big).unwrap();
        assert!(captured.over_limit && captured.bytes.is_empty());
        assert!(UserScannerProvider::capture_report(&dir.path().join("absent.json")).is_none());
    }
}
