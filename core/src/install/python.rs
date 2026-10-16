//! App-managed Python provider installation.
//!
//! Reviewed Python CLI providers (user-scanner, Sherlock, Maigret, socialscan) are
//! installed **without any system Python, pip, or pipx** using a pinned,
//! checksum-verified [`uv`](https://github.com/astral-sh/uv) runtime:
//!
//! 1. Bootstrap `uv`: if a reviewed `uv` is not already present, download the pinned
//!    release for the host architecture through the shared download → verify (SHA-256)
//!    → safe-extract → atomic-install pipeline into `<managed>/runtime/uv`.
//! 2. Run `uv tool install --python <pinned> <package>==<version>` as an executable +
//!    argument array (no shell). The package name and version come only from the
//!    reviewed [`manifest::python_package`] table. uv creates an **isolated** tool
//!    environment and installs a uv-managed CPython — nothing touches the system
//!    Python, `sudo`, or any system directory. All of uv's state (tool venvs, bin
//!    scripts, cache, Python installs, and HOME) is contained under the managed
//!    providers directory.
//! 3. The reviewed console script lands in `<managed>/python-bin`, which `ToolConfig`
//!    already searches, so the provider is discovered immediately afterwards.
//!
//! Security: no `sh -c`, no `curl | sh`, no sudo, no system-directory writes, no
//! arbitrary package name/version, bounded output, cancellable (process group killed).

use super::download::DownloadTransport;
use super::manifest::{self, Arch};
use super::{
    install_managed_artifact, InstallMethod, InstallOutcome, InstallReporter, InstallStage,
    InstallStatus, INSTALL_STDERR_CAP, INSTALL_STDOUT_CAP,
};
use crate::{
    error::{CoreError, Result},
    process::{self, RunOptions, ToolConfig},
};
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

/// The uv-managed CPython version requested for tool environments. python-build-standalone
/// publishes this; uv fetches it into the contained install dir on demand.
const PINNED_PYTHON: &str = "3.12";

/// Install a reviewed Python provider with the app-managed `uv` runtime.
pub fn python_install(
    tools: &ToolConfig,
    downloader: &dyn DownloadTransport,
    reporter: &dyn InstallReporter,
    provider_id: &str,
    cancelled: &AtomicBool,
    deadline: Instant,
) -> Result<InstallOutcome> {
    let method = InstallMethod::ManagedPython;
    let fail = |message: &str| InstallOutcome {
        provider_id: provider_id.to_owned(),
        method,
        status: InstallStatus::Failed,
        message: message.to_owned(),
        detail: None,
    };

    let Some(pkg) = manifest::python_package(provider_id) else {
        return Ok(InstallOutcome {
            provider_id: provider_id.to_owned(),
            method,
            status: InstallStatus::Unsupported,
            message: "This provider has no reviewed managed Python package.".into(),
            detail: None,
        });
    };
    let Some(managed_dir) = tools.managed_dir.clone() else {
        return Ok(InstallOutcome {
            provider_id: provider_id.to_owned(),
            method,
            status: InstallStatus::Unsupported,
            message: "The managed providers directory is unavailable.".into(),
            detail: None,
        });
    };

    // 1. Bootstrap uv (download+verify+extract the pinned release) if not present.
    let uv = match ensure_uv(
        tools,
        downloader,
        reporter,
        &managed_dir,
        cancelled,
        deadline,
    ) {
        Ok(uv) => uv,
        Err(error) if error.code == "Cancelled" => {
            return Ok(cancelled_outcome(provider_id, method))
        }
        Err(error) => {
            return Ok(fail(&format!(
                "Could not prepare the uv runtime: {}",
                error.message
            )))
        }
    };

    if cancelled.load(Ordering::SeqCst) {
        return Ok(cancelled_outcome(provider_id, method));
    }

    // 2. Contained uv directories under the managed providers directory.
    let tool_dir = managed_dir.join("python-tools");
    let bin_dir = managed_dir.join(crate::process::MANAGED_PYTHON_BIN);
    let cache_dir = managed_dir.join("uv-cache");
    let python_dir = managed_dir.join("python");
    let home_dir = managed_dir.join("uv-home");
    for dir in [&tool_dir, &bin_dir, &cache_dir, &python_dir, &home_dir] {
        std::fs::create_dir_all(dir)?;
    }

    // 3. Reviewed, fixed argv: install exactly package==version from the manifest.
    let spec = format!("{}=={}", pkg.package, pkg.version);
    let args = vec![
        "tool".to_string(),
        "install".to_string(),
        "--python".to_string(),
        PINNED_PYTHON.to_string(),
        "--force".to_string(),
        spec.clone(),
    ];
    let env = vec![
        (
            "UV_TOOL_DIR".into(),
            tool_dir.to_string_lossy().into_owned(),
        ),
        (
            "UV_TOOL_BIN_DIR".into(),
            bin_dir.to_string_lossy().into_owned(),
        ),
        (
            "UV_CACHE_DIR".into(),
            cache_dir.to_string_lossy().into_owned(),
        ),
        (
            "UV_PYTHON_INSTALL_DIR".into(),
            python_dir.to_string_lossy().into_owned(),
        ),
        // Only ever use a uv-managed CPython; never fall back to a system interpreter.
        ("UV_PYTHON_PREFERENCE".into(), "only-managed".into()),
        ("UV_NO_CONFIG".into(), "1".into()),
        ("HOME".into(), home_dir.to_string_lossy().into_owned()),
        ("NO_COLOR".into(), "1".into()),
    ];

    reporter.stage(InstallStage::Installing);
    reporter.info(&format!(
        "Installing {spec} into an isolated environment with uv."
    ));
    reporter.command(&uv, &args);
    let outcome = process::run_with(
        &uv,
        &args,
        cancelled,
        deadline,
        INSTALL_STDOUT_CAP,
        INSTALL_STDERR_CAP,
        &RunOptions {
            env,
            current_dir: Some(managed_dir.clone()),
        },
    )?;
    reporter.output(&outcome.stdout, &outcome.stderr);

    if outcome.cancelled {
        return Ok(cancelled_outcome(provider_id, method));
    }
    if outcome.timed_out || outcome.exit_status != Some(0) {
        let mut o = fail(&format!("uv could not install {spec}."));
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
            o.detail = Some(tail.chars().take(400).collect());
        }
        return Ok(o);
    }

    // 4. Verify the reviewed console script is now discoverable.
    reporter.stage(InstallStage::Checking);
    let script = bin_dir.join(pkg.executable);
    let Some(resolved) = process::executable_at(&script) else {
        return Ok(fail(&format!(
            "uv reported success but the {} executable was not found.",
            pkg.executable
        )));
    };
    reporter.info(&format!(
        "Installed {} to the managed Python bin directory.",
        pkg.executable
    ));
    Ok(InstallOutcome {
        provider_id: provider_id.to_owned(),
        method,
        status: InstallStatus::Succeeded,
        message: format!(
            "Installed {} {} with the managed uv runtime.",
            pkg.package, pkg.version
        ),
        detail: Some(resolved.display().to_string()),
    })
}

fn cancelled_outcome(provider_id: &str, method: InstallMethod) -> InstallOutcome {
    InstallOutcome {
        provider_id: provider_id.to_owned(),
        method,
        status: InstallStatus::Cancelled,
        message: "Installation cancelled.".into(),
        detail: None,
    }
}

/// Locate the pinned `uv`, downloading and verifying it into `<managed>/runtime` if it
/// is not already present (override, PATH, Homebrew, managed dir, or the runtime dir).
fn ensure_uv(
    tools: &ToolConfig,
    downloader: &dyn DownloadTransport,
    reporter: &dyn InstallReporter,
    managed_dir: &Path,
    cancelled: &AtomicBool,
    deadline: Instant,
) -> Result<PathBuf> {
    let runtime_dir = managed_dir.join(crate::process::MANAGED_RUNTIME);
    if let Some(uv) = tools.locate_in("uv", std::slice::from_ref(&runtime_dir)) {
        reporter.info("Using the existing uv runtime.");
        return Ok(uv);
    }
    let arch = Arch::host().ok_or_else(|| {
        CoreError::new(
            "Unsupported",
            "Unsupported architecture for the uv runtime.",
        )
    })?;
    let release = manifest::uv_release(arch).ok_or_else(|| {
        CoreError::new(
            "Unsupported",
            "No reviewed uv release for this architecture.",
        )
    })?;
    reporter.info(&format!(
        "Bootstrapping uv {} ({}).",
        release.version,
        arch.as_str()
    ));
    reporter.stage(InstallStage::Downloading);
    reporter.command(
        Path::new("https-download"),
        std::slice::from_ref(&release.url),
    );
    let artifact = release.as_artifact();
    let path = install_managed_artifact(downloader, &artifact, &runtime_dir, cancelled, deadline)?;
    Ok(path)
}
