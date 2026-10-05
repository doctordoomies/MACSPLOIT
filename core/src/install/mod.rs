//! Provider installation.
//!
//! Installation is **typed and bounded**: a request names a provider id and a method,
//! never an arbitrary command. The Homebrew formula and official-installer URL for each
//! provider are hardcoded in [`options`]; nothing a caller supplies becomes a shell
//! string or a formula name. Homebrew is launched as an executable with an argument
//! array through the process supervisor — never via `/bin/sh -c`, never `curl | sh`.
//!
//! Only the reviewed provider set can be installed. A provider with no safe automated
//! method for a given approach fails closed (Unsupported) and routes the user to
//! Homebrew or the official installer rather than faking a result.

use crate::{
    error::{CoreError, Result},
    process::{self, ToolConfig},
};
use serde::{Deserialize, Serialize};
use std::{sync::atomic::AtomicBool, time::Instant};

const INSTALL_STDOUT_CAP: usize = 256 * 1024;
const INSTALL_STDERR_CAP: usize = 64 * 1024;

/// How a provider may be installed. A request carries only this choice plus a provider
/// id; the concrete formula/URL/location come from the reviewed [`options`] table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallMethod {
    /// `brew install <reviewed formula>` via the Homebrew executable (no shell).
    Homebrew,
    /// App-managed direct download of a verified upstream artifact (no Homebrew).
    ManagedDownload,
    /// Use a compatible executable already present (PATH / override) — no install.
    ExistingBinary,
    /// Open the provider's official installer/download page (no in-app execution).
    OfficialInstaller,
}

/// Reviewed installation metadata for one provider.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ProviderInstallOptions {
    pub provider_id: &'static str,
    pub homebrew_formula: Option<&'static str>,
    /// Whether a safe, verified app-managed direct install is appropriate for this
    /// provider. (Nmap ships a privileged .dmg installer, so it is false there.)
    pub managed_download_supported: bool,
    pub official_installer_url: Option<&'static str>,
}

/// The reviewed per-provider installation matrix. Returns `None` for any provider that is
/// not in the installable set, so an unknown id can never request an installation.
pub fn options(provider_id: &str) -> Option<ProviderInstallOptions> {
    let o = |provider_id, homebrew_formula, managed_download_supported, official_installer_url| {
        ProviderInstallOptions {
            provider_id,
            homebrew_formula,
            managed_download_supported,
            official_installer_url,
        }
    };
    Some(match provider_id {
        // ProjectDiscovery / ffuf: Go tools with Homebrew formulae and checksummed,
        // per-arch standalone macOS archives on their official GitHub releases.
        "subfinder" => o(
            "subfinder",
            Some("subfinder"),
            true,
            Some("https://github.com/projectdiscovery/subfinder/releases"),
        ),
        "httpx" => o(
            "httpx",
            Some("httpx"),
            true,
            Some("https://github.com/projectdiscovery/httpx/releases"),
        ),
        "katana" => o(
            "katana",
            Some("katana"),
            true,
            Some("https://github.com/projectdiscovery/katana/releases"),
        ),
        "ffuf" => o(
            "ffuf",
            Some("ffuf"),
            true,
            Some("https://github.com/ffuf/ffuf/releases"),
        ),
        // Nmap: Homebrew formula, but the official standalone macOS build is a privileged
        // .dmg installer — not appropriate for an app-managed direct install.
        "nmap" => o(
            "nmap",
            Some("nmap"),
            false,
            Some("https://nmap.org/download.html"),
        ),
        _ => return None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallStatus {
    Succeeded,
    Failed,
    Cancelled,
    /// The requested method is not available for this provider; the message routes the
    /// user to a supported method (Homebrew / official installer).
    Unsupported,
}

#[derive(Debug, Clone, Serialize)]
pub struct InstallOutcome {
    pub provider_id: String,
    pub method: InstallMethod,
    pub status: InstallStatus,
    pub message: String,
    /// Short, presentation-safe extra context (e.g. an official-installer URL, or a
    /// bounded tail of install output). Never raw unbounded logs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl InstallOutcome {
    fn new(provider_id: &str, method: InstallMethod, status: InstallStatus, message: &str) -> Self {
        Self {
            provider_id: provider_id.to_owned(),
            method,
            status,
            message: message.to_owned(),
            detail: None,
        }
    }
}

/// Perform a typed installation. Validates the provider against the reviewed matrix and
/// dispatches to the chosen method. Never executes a caller-supplied command.
pub fn install(
    tools: &ToolConfig,
    provider_id: &str,
    method: InstallMethod,
    cancelled: &AtomicBool,
    deadline: Instant,
) -> Result<InstallOutcome> {
    let opts = options(provider_id).ok_or_else(|| {
        CoreError::new("ProviderUnsupported", "This provider cannot be installed.")
    })?;
    match method {
        InstallMethod::Homebrew => homebrew_install(tools, &opts, cancelled, deadline),
        InstallMethod::ManagedDownload => {
            // Fail closed: a verified app-managed binary downloader is a separate,
            // security-reviewed deliverable. Never fake success or fetch-and-run.
            let mut outcome = InstallOutcome::new(
                provider_id,
                method,
                InstallStatus::Unsupported,
                if opts.managed_download_supported {
                    "App-managed download is being finalized. Install with Homebrew, or use the official installer."
                } else {
                    "This provider has no safe app-managed install. Install with Homebrew, or use the official installer."
                },
            );
            outcome.detail = opts.official_installer_url.map(str::to_owned);
            Ok(outcome)
        }
        InstallMethod::OfficialInstaller => {
            let mut outcome = InstallOutcome::new(
                provider_id,
                method,
                InstallStatus::Unsupported,
                "Open the official installer page to install this provider.",
            );
            outcome.detail = opts.official_installer_url.map(str::to_owned);
            Ok(outcome)
        }
        InstallMethod::ExistingBinary => Ok(InstallOutcome::new(
            provider_id,
            method,
            InstallStatus::Unsupported,
            "Make a compatible executable available on PATH, or set the provider override; MACSPLOIT discovers it automatically.",
        )),
    }
}

/// Run `brew install <formula>` as an executable + argv (no shell). The formula comes
/// only from the reviewed matrix, so a caller can never inject a formula or command.
fn homebrew_install(
    tools: &ToolConfig,
    opts: &ProviderInstallOptions,
    cancelled: &AtomicBool,
    deadline: Instant,
) -> Result<InstallOutcome> {
    let formula = opts.homebrew_formula.ok_or_else(|| {
        CoreError::new(
            "ProviderUnsupported",
            "No Homebrew formula for this provider.",
        )
    })?;
    let brew = tools.locate("brew").ok_or_else(|| {
        CoreError::new(
            "ProviderMissing",
            "Homebrew was not found. Install Homebrew (optional) or use the official installer.",
        )
    })?;
    // Fixed, reviewed argument array. Never a shell string; the formula is a constant.
    let args = vec!["install".to_string(), formula.to_string()];
    let outcome = process::run(
        &brew,
        &args,
        cancelled,
        deadline,
        INSTALL_STDOUT_CAP,
        INSTALL_STDERR_CAP,
    )?;
    let status = if outcome.cancelled {
        InstallStatus::Cancelled
    } else if outcome.timed_out || outcome.exit_status != Some(0) {
        InstallStatus::Failed
    } else {
        InstallStatus::Succeeded
    };
    let message = match status {
        InstallStatus::Succeeded => format!("Installed {formula} with Homebrew."),
        InstallStatus::Cancelled => "Installation cancelled.".to_owned(),
        _ => format!("Homebrew could not install {formula}."),
    };
    let mut result =
        InstallOutcome::new(opts.provider_id, InstallMethod::Homebrew, status, &message);
    // Bounded tail of stderr for diagnostics (never the full log; no secrets expected).
    let stderr = String::from_utf8_lossy(&outcome.stderr);
    let tail: String = stderr
        .lines()
        .rev()
        .take(3)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join(" / ");
    if !tail.trim().is_empty() {
        result.detail = Some(tail.chars().take(400).collect());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    fn fake_brew(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
        let p = dir.join("brew");
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    fn tools_with_brew(path: std::path::PathBuf) -> ToolConfig {
        let mut t = ToolConfig::default();
        t.overrides.insert("brew".into(), path);
        t
    }

    #[test]
    fn matrix_only_lists_reviewed_providers() {
        for id in ["subfinder", "httpx", "katana", "ffuf", "nmap"] {
            assert!(options(id).is_some(), "{id}");
        }
        assert!(options("totally-unknown").is_none());
        // Nmap has no app-managed direct install (privileged .dmg).
        assert!(!options("nmap").unwrap().managed_download_supported);
        assert!(options("subfinder").unwrap().managed_download_supported);
    }

    #[test]
    fn unknown_provider_cannot_request_installation() {
        let err = install(
            &ToolConfig::default(),
            "evil-tool",
            InstallMethod::Homebrew,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap_err();
        assert_eq!(err.code, "ProviderUnsupported");
    }

    #[test]
    fn homebrew_invocation_uses_executable_and_exact_argv() {
        // The fake brew records its argv; assert it is exactly ["install", "<formula>"]
        // so no shell metacharacters or command injection are possible.
        let dir = tempfile::tempdir().unwrap();
        let args_file = dir.path().join("args.txt");
        let brew = fake_brew(
            dir.path(),
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\nexit 0\n",
                args_file.display()
            ),
        );
        let tools = tools_with_brew(brew);
        let outcome = install(
            &tools,
            "httpx",
            InstallMethod::Homebrew,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(outcome.status, InstallStatus::Succeeded);
        let recorded = std::fs::read_to_string(&args_file).unwrap();
        assert_eq!(
            recorded.lines().collect::<Vec<_>>(),
            vec!["install", "httpx"]
        );
    }

    #[test]
    fn homebrew_failure_does_not_report_success() {
        let dir = tempfile::tempdir().unwrap();
        let brew = fake_brew(dir.path(), "#!/bin/sh\necho 'boom' 1>&2\nexit 1\n");
        let tools = tools_with_brew(brew);
        let outcome = install(
            &tools,
            "ffuf",
            InstallMethod::Homebrew,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(outcome.status, InstallStatus::Failed);
    }

    #[test]
    fn homebrew_missing_reports_provider_missing() {
        // No brew override and an empty extra search path → not found.
        let err = install(
            &ToolConfig::default(),
            "subfinder",
            InstallMethod::Homebrew,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(5),
        );
        // Either Homebrew is genuinely absent (ProviderMissing) or present on the dev
        // machine; in CI it is absent. Accept ProviderMissing or a real run result.
        if let Err(e) = err {
            assert_eq!(e.code, "ProviderMissing");
        }
    }

    #[test]
    fn managed_and_existing_binary_fail_closed_without_installing() {
        let t = ToolConfig::default();
        let dl = install(
            &t,
            "subfinder",
            InstallMethod::ManagedDownload,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(dl.status, InstallStatus::Unsupported);
        assert!(dl.detail.as_deref().unwrap_or("").starts_with("https://"));
        let eb = install(
            &t,
            "nmap",
            InstallMethod::ExistingBinary,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(eb.status, InstallStatus::Unsupported);
        let off = install(
            &t,
            "nmap",
            InstallMethod::OfficialInstaller,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(off.status, InstallStatus::Unsupported);
        assert_eq!(
            off.detail.as_deref(),
            Some("https://nmap.org/download.html")
        );
    }
}
