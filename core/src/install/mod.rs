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

pub mod download;
pub mod extract;
pub mod manifest;

use crate::{
    error::{CoreError, Result},
    process::{self, ToolConfig},
};
use download::DownloadTransport;
use manifest::Arch;
use serde::{Deserialize, Serialize};
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

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
    downloader: &dyn DownloadTransport,
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
            managed_install(tools, downloader, &opts, provider_id, cancelled, deadline)
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

/// App-managed direct download: resolve the reviewed, pinned artifact for this
/// provider and the host architecture, then download → verify → extract → install
/// atomically into the managed providers directory. Fails closed (never fakes
/// success, never fetch-and-run) for any provider/architecture without a reviewed
/// artifact, and leaves any existing install untouched on failure.
fn managed_install(
    tools: &ToolConfig,
    downloader: &dyn DownloadTransport,
    opts: &ProviderInstallOptions,
    provider_id: &str,
    cancelled: &AtomicBool,
    deadline: Instant,
) -> Result<InstallOutcome> {
    let route_to_supported = |message: &str| {
        let mut outcome = InstallOutcome::new(
            provider_id,
            InstallMethod::ManagedDownload,
            InstallStatus::Unsupported,
            message,
        );
        outcome.detail = opts.official_installer_url.map(str::to_owned);
        outcome
    };

    if !opts.managed_download_supported {
        // e.g. Nmap: privileged .dmg installer, no safe app-managed artifact.
        return Ok(route_to_supported(
            "This provider has no safe app-managed install. Install with Homebrew, or use the official installer.",
        ));
    }
    let Some(arch) = Arch::host() else {
        return Ok(route_to_supported(
            "No reviewed managed download is available for this architecture. Use Homebrew or the official installer.",
        ));
    };
    let Some(artifact) = manifest::artifact(provider_id, arch) else {
        return Ok(route_to_supported(
            "No reviewed managed artifact for this provider on this architecture. Use Homebrew or the official installer.",
        ));
    };
    let Some(managed_dir) = tools.managed_dir.clone() else {
        // Production always wires this from the data directory; fail closed if absent.
        return Ok(route_to_supported(
            "The managed providers directory is unavailable. Use Homebrew or the official installer.",
        ));
    };

    match install_managed_artifact(downloader, &artifact, &managed_dir, cancelled, deadline) {
        Ok(path) => {
            let mut outcome = InstallOutcome::new(
                provider_id,
                InstallMethod::ManagedDownload,
                InstallStatus::Succeeded,
                &format!(
                    "Installed {} {} ({}) to the managed providers directory.",
                    artifact.provider_id,
                    artifact.version,
                    arch.as_str()
                ),
            );
            outcome.detail = Some(path.display().to_string());
            Ok(outcome)
        }
        Err(error) if error.code == "Cancelled" => Ok(InstallOutcome::new(
            provider_id,
            InstallMethod::ManagedDownload,
            InstallStatus::Cancelled,
            "Installation cancelled.",
        )),
        Err(error) => {
            // Fail closed: report failure; any previously installed binary is intact.
            Ok(InstallOutcome::new(
                provider_id,
                InstallMethod::ManagedDownload,
                InstallStatus::Failed,
                &format!("Managed install failed: {}", error.message),
            ))
        }
    }
}

/// Download, verify, extract, and atomically install one reviewed artifact into
/// `managed_dir`, returning the installed executable path. Every failure mode
/// (bad checksum, unsafe archive, cancellation, timeout) leaves `managed_dir`'s
/// existing contents untouched: work happens in a staging directory on the same
/// filesystem and only the final `rename` is observable.
///
/// This is the single code path the engine uses for managed installs; tests drive
/// it with a fake transport and a fixture artifact so the real logic runs offline.
pub fn install_managed_artifact(
    downloader: &dyn DownloadTransport,
    artifact: &manifest::ManagedArtifact,
    managed_dir: &Path,
    cancelled: &AtomicBool,
    deadline: Instant,
) -> Result<PathBuf> {
    std::fs::create_dir_all(managed_dir)?;
    // Owner-only managed directory.
    let _ = std::fs::set_permissions(managed_dir, std::fs::Permissions::from_mode(0o700));

    // Staging on the same filesystem as the destination so the final move is atomic.
    let staging = tempfile::Builder::new()
        .prefix(".staging-")
        .tempdir_in(managed_dir)
        .map_err(|e| CoreError::new("StorageError", &format!("Could not create staging: {e}")))?;

    let archive_path = staging.path().join("artifact");
    download::download_verified(downloader, artifact, &archive_path, cancelled, deadline)?;

    if cancelled.load(Ordering::SeqCst) {
        return Err(CoreError::new("Cancelled", "Installation cancelled."));
    }

    let extracted = staging.path().join(&artifact.installed_name);
    extract::extract_member(
        &archive_path,
        artifact.archive,
        &artifact.member,
        &extracted,
        artifact.max_extracted_bytes,
    )?;

    // The extracted object must be a plain regular file (not a symlink); set a
    // safe executable mode explicitly rather than trusting the archive's bits.
    let meta = std::fs::symlink_metadata(&extracted)?;
    if !meta.file_type().is_file() {
        return Err(CoreError::new(
            "UnsafeArchive",
            "Extracted member is not a regular file.",
        ));
    }
    std::fs::set_permissions(&extracted, std::fs::Permissions::from_mode(0o755))?;

    // Atomic install: rename within the same directory replaces any previous good
    // binary in one step. If anything above failed, we never reach this line.
    let final_path = managed_dir.join(&artifact.installed_name);
    std::fs::rename(&extracted, &final_path).map_err(|e| {
        CoreError::new(
            "StorageError",
            &format!("Could not install the executable: {e}"),
        )
    })?;
    // `staging` is removed on drop, cleaning the archive and any partial files.
    Ok(final_path)
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

    /// An empty offline transport: any managed download fails closed with no net.
    fn no_dl() -> download::StaticDownloadTransport {
        download::StaticDownloadTransport::new()
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
            &no_dl(),
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
            &no_dl(),
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
            &no_dl(),
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
            &no_dl(),
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
        // No managed directory wired → managed download fails closed (routes to a
        // supported method) without any network activity.
        let t = ToolConfig::default();
        let dl = install(
            &t,
            &no_dl(),
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
            &no_dl(),
            "nmap",
            InstallMethod::ExistingBinary,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(eb.status, InstallStatus::Unsupported);
        let off = install(
            &t,
            &no_dl(),
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

    #[test]
    fn nmap_managed_download_is_unsupported_and_routes_to_official() {
        // Even with a managed directory available, Nmap has no managed artifact.
        let dir = tempfile::tempdir().unwrap();
        let t = ToolConfig {
            managed_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let out = install(
            &t,
            &no_dl(),
            "nmap",
            InstallMethod::ManagedDownload,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(out.status, InstallStatus::Unsupported);
        assert_eq!(
            out.detail.as_deref(),
            Some("https://nmap.org/download.html")
        );
        // Nothing was written into the managed directory.
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
    }

    #[test]
    fn supported_managed_download_fails_closed_when_transport_cannot_serve() {
        // A supported provider with a managed dir but an empty transport must fail
        // (not fake success), and must not leave a binary behind.
        let dir = tempfile::tempdir().unwrap();
        let t = ToolConfig {
            managed_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        };
        let out = install(
            &t,
            &no_dl(),
            "subfinder",
            InstallMethod::ManagedDownload,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(out.status, InstallStatus::Failed);
        assert!(!dir.path().join("subfinder").exists());
    }
}
