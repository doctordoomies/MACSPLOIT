//! PhoneInfoga (sundowndev/phoneinfoga, GPL-3.0, invoked as a separate executable) —
//! Phone OSINT provider for one explicit international number.
//!
//! Verified against upstream source at v2.11.0 (latest release tag; repository
//! active in 2026). Behavior this integration depends on:
//!
//! * Executable: `phoneinfoga` (Homebrew `brew install phoneinfoga`, or the signed
//!   GitHub release binary for darwin amd64/arm64). Upstream's `curl | bash`
//!   installer is never suggested.
//! * Version: `phoneinfoga version` prints `PhoneInfoga v<X.Y.Z>-<commit>`.
//! * Scan: `phoneinfoga scan --number=<E.164>` validates the number with
//!   libphonenumber, runs the enabled scanners, and prints results with a fixed
//!   console renderer: `Results for <scanner>` sections of `Field: value` lines,
//!   an optional `The following scanners returned errors:` block of
//!   `<scanner>: <error>` lines, and a final `<N> scanner(s) succeeded` line.
//!   The `scan` CLI has no JSON output (JSON exists only through `phoneinfoga
//!   serve`, a local HTTP server MACSPLOIT does not run), so this provider parses
//!   that renderer with a strict line grammar; the raw output is kept as evidence.
//!   An invalid number exits 1 with the error on stderr.
//! * Scanners: `local` (offline libphonenumber facts: E.164/international/local
//!   formats, country code, country, carrier), `ovh` (OVH Telecom's public number
//!   range lookup; only for its supported countries, otherwise skipped by its own
//!   dry-run), `numverify` and `googlecse` (API-key services — skipped without keys),
//!   and `googlesearch` (generates Google dork links; it discovers nothing).
//!   MACSPLOIT disables `numverify`, `googlecse`, and `googlesearch` explicitly so
//!   the result is deterministic and no API-key service or search engine is used.
//!   `--plugin` and `--env-file` are never passed; the private working directory has
//!   no `.env`.
//!
//! Boundaries: no calls, SMS, OTP, account recovery, or subscriber lookup; one
//! explicit number → one bounded run; no pivots.

use super::osint_cli::{self, STDERR_CAP, STDOUT_CAP};
use super::{
    Capability, Execution, NetworkActivity, ParsedOutput, Provider, ProviderContext,
    ProviderMetadata, ProviderSetup, RiskClass,
};
use crate::{
    assets::{Asset, Discovery},
    error::{CoreError, Result},
    osint::{self, PhoneFacts, Subject},
    process::{self, Installation, RunOptions, ToolConfig},
    targets::TargetType,
};
use serde_json::{Map, Value};
use std::{
    path::PathBuf,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

pub struct PhoneInfogaProvider;

pub const PHONEINFOGA_TOOL: &str = "phoneinfoga";
pub const RUN_TIMEOUT: Duration = Duration::from_secs(120);
/// Upstream series whose CLI/console format was verified.
pub const SUPPORTED_SERIES: &str = "2.";
/// Scanners MACSPLOIT always disables (API-key services and dork generation).
pub const DISABLED_SCANNERS: &[&str] = &["numverify", "googlecse", "googlesearch"];
/// Maximum console lines considered.
const MAX_LINES: usize = 2000;

impl PhoneInfogaProvider {
    /// The exact, bounded argument array.
    pub fn arguments(subject: &Subject) -> Vec<String> {
        let mut args = vec!["scan".to_owned(), format!("--number={}", subject.query)];
        for scanner in DISABLED_SCANNERS {
            args.push(format!("--disable={scanner}"));
        }
        args
    }

    fn locate(tools: &ToolConfig) -> Option<PathBuf> {
        osint_cli::locate(tools, PHONEINFOGA_TOOL)
    }

    fn subject_for(target: &str, capability: Capability) -> Result<Subject> {
        if capability != Capability::PhoneOsint {
            return Err(CoreError::new(
                "ProviderUnsupported",
                "PhoneInfoga only provides phone OSINT.",
            ));
        }
        Subject::from_target(TargetType::PhoneNumber, target)
    }

    /// Remove ANSI CSI escape sequences (defensive; color is disabled anyway).
    fn strip_ansi(line: &str) -> String {
        let mut out = String::with_capacity(line.len());
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                if chars.peek() == Some(&'[') {
                    chars.next();
                    for next in chars.by_ref() {
                        if next.is_ascii_alphabetic() {
                            break;
                        }
                    }
                }
                continue;
            }
            out.push(c);
        }
        out
    }

    fn scanner_name(raw: &str) -> Option<String> {
        let name = osint::clean_text(raw, osint::MAX_KEY_BYTES);
        (!name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')))
        .then_some(name)
    }

    /// Parse the console renderer. Returns (sections, errors, malformed line count,
    /// trailer seen).
    fn parse_console(text: &str) -> (Vec<PhoneFacts>, Vec<(String, String)>, usize, bool) {
        enum State {
            Outside,
            Section(usize),
            Errors,
        }
        let mut sections: Vec<PhoneFacts> = Vec::new();
        let mut errors = Vec::new();
        let mut malformed = 0usize;
        let mut trailer = false;
        let mut state = State::Outside;
        for raw in text.lines().take(MAX_LINES) {
            let line = Self::strip_ansi(raw);
            let trimmed = line.trim();
            if trimmed.is_empty() {
                state = State::Outside;
                continue;
            }
            if let Some(name) = trimmed.strip_prefix("Results for ") {
                match Self::scanner_name(name) {
                    Some(source) if sections.len() < osint::MAX_METADATA_KEYS => {
                        sections.push(PhoneFacts {
                            source,
                            facts: Map::new(),
                        });
                        state = State::Section(sections.len() - 1);
                    }
                    _ => {
                        malformed += 1;
                        state = State::Outside;
                    }
                }
                continue;
            }
            if trimmed == "The following scanners returned errors:" {
                state = State::Errors;
                continue;
            }
            if let Some(count) = trimmed.strip_suffix(" scanner(s) succeeded") {
                if count.chars().all(|c| c.is_ascii_digit()) {
                    trailer = true;
                    state = State::Outside;
                    continue;
                }
            }
            if trimmed.starts_with("Running scan for phone number") {
                continue;
            }
            match state {
                State::Section(index) => match trimmed.split_once(':') {
                    // A nested struct/slice header (`Items:`) carries no value.
                    Some((_, value)) if value.trim().is_empty() => {}
                    Some((label, value)) => {
                        let facts = &mut sections[index].facts;
                        match osint::fact_key(label) {
                            Some(key)
                                if !facts.contains_key(&key)
                                    && facts.len() < osint::MAX_METADATA_KEYS =>
                            {
                                let value = osint::clean_text(value, osint::MAX_FIELD_BYTES);
                                facts.insert(key, Value::String(value));
                            }
                            Some(_) => {}
                            None => malformed += 1,
                        }
                    }
                    None => malformed += 1,
                },
                State::Errors => match trimmed.split_once(':') {
                    Some((name, message)) => match Self::scanner_name(name) {
                        Some(source) if errors.len() < osint::MAX_SUMMARY_LIST => errors
                            .push((source, osint::clean_text(message, osint::MAX_FIELD_BYTES))),
                        Some(_) => {}
                        None => malformed += 1,
                    },
                    None => malformed += 1,
                },
                State::Outside => malformed += 1,
            }
        }
        (sections, errors, malformed, trailer)
    }
}

impl Provider for PhoneInfogaProvider {
    fn setup(&self) -> Option<ProviderSetup> {
        Some(ProviderSetup {
            install_command: Some("brew install phoneinfoga".into()),
            homepage: Some("https://github.com/sundowndev/phoneinfoga".into()),
            documentation: Some("https://sundowndev.github.io/phoneinfoga/".into()),
        })
    }

    fn metadata(&self) -> ProviderMetadata {
        ProviderMetadata {
            id: "phoneinfoga".into(),
            name: "PhoneInfoga".into(),
            description: "Phone OSINT: public numbering metadata (formats, country, carrier, OVH public number ranges) for one explicit international number. No calls, SMS, API-key services, or search-engine dorks.".into(),
            version: "external".into(),
            capabilities: vec![Capability::PhoneOsint],
            supported_target_types: vec![TargetType::PhoneNumber],
            // Offline libphonenumber facts plus OVH's public number-range API; the
            // subscriber's line is never contacted.
            risk_class: RiskClass::Passive,
            network_activity: NetworkActivity::Network,
        }
    }

    fn installation(&self, tools: &ToolConfig) -> Installation {
        let Some(executable) = Self::locate(tools) else {
            return Installation::Missing;
        };
        let Ok(dir) = osint_cli::private_dir("macsploit-phoneinfoga-") else {
            return Installation::ExecutionError {
                message: "Could not prepare a private directory for the version probe.".into(),
            };
        };
        let cancelled = AtomicBool::new(false);
        match process::run_with(
            &executable,
            &["version".into()],
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
                    .find(|l| l.contains("PhoneInfoga"))
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
        let subject = Self::subject_for(target, capability)?;
        let executable = Self::locate(ctx.tools).ok_or_else(|| {
            CoreError::new(
                "ProviderMissing",
                "PhoneInfoga is not installed. Install it (brew install phoneinfoga) and refresh providers.",
            )
        })?;
        let dir = osint_cli::private_dir("macsploit-phoneinfoga-")?;
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
            artifacts: Vec::new(),
            cancelled: outcome.cancelled,
        })
    }

    fn parse(&self, execution: &Execution) -> Result<Vec<Discovery>> {
        Ok(self.parse_outcome(execution)?.discoveries)
    }

    fn parse_outcome(&self, execution: &Execution) -> Result<ParsedOutput> {
        let subject = Self::subject_for(&execution.target, execution.capability)?;
        if execution.stdout.len() >= STDOUT_CAP {
            return Err(CoreError::new(
                "BudgetExceeded",
                "PhoneInfoga output exceeded its size bound; raw output is preserved as evidence.",
            ));
        }
        let text = String::from_utf8_lossy(&execution.stdout);
        let (sections, errors, malformed, trailer) = Self::parse_console(&text);
        if !trailer {
            return Err(CoreError::new(
                "ProviderFailure",
                "PhoneInfoga output is incomplete or not in the reviewed console format.",
            ));
        }
        Ok(osint::build_phone_output(
            "phoneinfoga",
            &subject,
            sections,
            errors,
            malformed,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assets::AssetType;

    fn exec(target: &str, stdout: &str) -> Execution {
        Execution {
            target: target.into(),
            capability: Capability::PhoneOsint,
            command: vec!["phoneinfoga".into()],
            stdout: stdout.as_bytes().to_vec(),
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

    const VALID: &str = "Running scan for phone number +33199001234...\n\nResults for local\nRaw local: 0199001234\nLocal: 01 99 00 12 34\nE164: +33199001234\nInternational: 33199001234\nCountry code: 33\nCountry: FR\nCarrier: \n\nResults for ovh\nFound: true\nNumber range: 0199xxxxxx\nCity: Paris\n\n2 scanner(s) succeeded\n";

    #[test]
    fn metadata_and_arguments_disable_key_services_and_dorks() {
        let m = PhoneInfogaProvider.metadata();
        assert_eq!(m.id, "phoneinfoga");
        assert_eq!(m.capabilities, vec![Capability::PhoneOsint]);
        assert_eq!(m.supported_target_types, vec![TargetType::PhoneNumber]);
        assert_eq!(m.risk_class, RiskClass::Passive);
        let subject = Subject::from_target(TargetType::PhoneNumber, "+12025550143").unwrap();
        let args = PhoneInfogaProvider::arguments(&subject);
        assert_eq!(
            args,
            [
                "scan",
                "--number=+12025550143",
                "--disable=numverify",
                "--disable=googlecse",
                "--disable=googlesearch"
            ]
        );
        assert!(!args
            .iter()
            .any(|a| a.starts_with("--plugin") || a.starts_with("--env-file")));
        assert_eq!(
            PhoneInfogaProvider
                .setup()
                .unwrap()
                .install_command
                .as_deref(),
            Some("brew install phoneinfoga")
        );
    }

    #[test]
    fn parses_sections_into_one_subject_observation() {
        let out = PhoneInfogaProvider
            .parse_outcome(&exec("+33199001234", VALID))
            .unwrap();
        assert!(!out.partial);
        assert_eq!(out.discoveries.len(), 1);
        let d = &out.discoveries[0];
        assert_eq!(
            (d.asset_type, d.value.as_str()),
            (AssetType::PhoneNumber, "+33199001234")
        );
        let meta = &d.observation.as_ref().unwrap().metadata;
        assert_eq!(meta["sources"]["local"]["country"], "FR");
        assert_eq!(meta["sources"]["local"]["country_code"], "33");
        // An empty upstream value (unknown carrier) is omitted, never invented.
        assert!(meta["sources"]["local"]["carrier"].is_null());
        assert_eq!(meta["sources"]["ovh"]["city"], "Paris");
        assert_eq!(meta["subject_kind"], "PHONE");
        assert!(meta["identity_note"]
            .as_str()
            .unwrap()
            .contains("subscriber"));
    }

    #[test]
    fn scanner_errors_and_mismatched_e164_are_partial() {
        let text = "Results for local\nE164: +12025550199\nCountry: US\n\nThe following scanners returned errors:\novh: upstream timeout\n\n1 scanner(s) succeeded\n";
        let out = PhoneInfogaProvider
            .parse_outcome(&exec("+12025550143", text))
            .unwrap();
        assert!(out.partial);
        let s = out.summary.unwrap();
        assert_eq!(s["errors"][0]["source"], "ovh");
        assert_eq!(s["reported_e164_mismatch"], "+12025550199");
    }

    #[test]
    fn zero_results_complete_with_only_the_subject() {
        let out = PhoneInfogaProvider
            .parse_outcome(&exec(
                "+12025550143",
                "Running scan for phone number +12025550143...\n\n0 scanner(s) succeeded\n",
            ))
            .unwrap();
        assert!(!out.partial);
        assert_eq!(out.summary.unwrap()["counts"]["sources_reported"], 0);
    }

    #[test]
    fn malformed_truncated_and_oversized_output_fail_cleanly() {
        for text in ["garbage without a trailer", "Results for local\nE164: +1\n"] {
            assert_eq!(
                PhoneInfogaProvider
                    .parse_outcome(&exec("+12025550143", text))
                    .unwrap_err()
                    .code,
                "ProviderFailure"
            );
        }
        let big = "x".repeat(STDOUT_CAP);
        assert_eq!(
            PhoneInfogaProvider
                .parse_outcome(&exec("+12025550143", &big))
                .unwrap_err()
                .code,
            "BudgetExceeded"
        );
        // Stray lines are counted and make the run partial, never trusted.
        let noisy = format!("{VALID}unexpected trailing noise\n");
        assert!(
            PhoneInfogaProvider
                .parse_outcome(&exec("+33199001234", &noisy))
                .unwrap()
                .partial
        );
    }

    #[test]
    fn untrusted_values_are_bounded_and_escapes_stripped() {
        let long = "y".repeat(4000);
        let text = format!("Results for local\n\u{1b}[33mCountry: FR\u{1b}[0m\nCarrier: {long}\u{202e}\n\n1 scanner(s) succeeded\n");
        let out = PhoneInfogaProvider
            .parse_outcome(&exec("+33199001234", &text))
            .unwrap();
        let s = out.summary.unwrap();
        assert_eq!(s["sources"]["local"]["country"], "FR");
        assert!(s["sources"]["local"]["carrier"].as_str().unwrap().len() <= osint::MAX_FIELD_BYTES);
    }

    #[test]
    fn rejects_non_phone_capabilities_and_subjects() {
        let mut e = exec("@octo", VALID);
        assert!(PhoneInfogaProvider.parse_outcome(&e).is_err());
        e.target = "+33199001234".into();
        e.capability = Capability::EmailOsint;
        assert!(PhoneInfogaProvider.parse_outcome(&e).is_err());
    }

    #[test]
    fn missing_executable_reports_missing() {
        let mut tools = ToolConfig::default();
        tools
            .overrides
            .insert(PHONEINFOGA_TOOL.into(), "/nonexistent/phoneinfoga".into());
        assert_eq!(
            PhoneInfogaProvider.installation(&tools),
            Installation::Missing
        );
    }
}
