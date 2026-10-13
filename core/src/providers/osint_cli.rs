//! Shared plumbing for pipx/pip-installed command-line OSINT providers
//! (Sherlock, Maigret, socialscan). This is deliberately small, mechanical, and
//! security-sensitive: executable discovery, a private contained run directory,
//! a bounded symlink-safe artifact capture, and a version classification. The
//! provider-neutral normalization lives in [`crate::osint`]; per-tool CLI and
//! parsing live in each provider module. Nothing here interprets a shell.

use super::{Capability, ExecutionArtifact};
use crate::{
    error::{CoreError, Result},
    osint::Subject,
    process::{Installation, ToolConfig},
    targets::TargetType,
};
use std::{
    io::Read,
    path::{Path, PathBuf},
};

/// Bounded stdout capture for a provider run.
pub const STDOUT_CAP: usize = 256 * 1024;
/// Bounded stderr capture for a provider run.
pub const STDERR_CAP: usize = 64 * 1024;
/// A captured structured report becomes its own evidence record, capped at 1 MiB.
pub const REPORT_CAP: u64 = 1024 * 1024;

/// pipx/pip install console scripts into `$PIPX_BIN_DIR`, `~/.local/bin`, or
/// (Homebrew Python) the usual bin dirs. The app starts the core with a minimal
/// `PATH`, so these fallbacks are searched after `PATH` by `locate_in`.
pub fn pipx_directories() -> Vec<PathBuf> {
    let mut directories = Vec::new();
    if let Some(dir) = std::env::var_os("PIPX_BIN_DIR") {
        directories.push(PathBuf::from(dir));
    }
    if let Some(home) = std::env::var_os("HOME") {
        directories.push(PathBuf::from(&home).join(".local/bin"));
    }
    directories
}

/// Locate a pipx/pip-installed OSINT executable without executing it.
pub fn locate(tools: &ToolConfig, tool: &str) -> Option<PathBuf> {
    tools.locate_in(tool, &pipx_directories())
}

/// Validate that an OSINT run is a username workflow and build the strict subject.
/// These three providers are username-only in this wave.
pub fn username_subject(target: &str, capability: Capability) -> Result<Subject> {
    if capability != Capability::UsernameOsint {
        return Err(CoreError::new(
            "ProviderUnsupported",
            "This OSINT provider only supports username OSINT.",
        ));
    }
    Subject::from_target(TargetType::Username, target)
}

/// A private, contained run directory. Reports and any dotfile writes stay here
/// (callers set it as the working directory and `HOME`), and it is removed on drop.
pub fn private_dir(prefix: &str) -> Result<tempfile::TempDir> {
    Ok(tempfile::Builder::new().prefix(prefix).tempdir()?)
}

/// Environment for every invocation: no color/paging, deterministic encoding, and a
/// contained `HOME` so a tool cannot read or write the operator's real home.
pub fn base_env(home: &Path) -> Vec<(String, String)> {
    vec![
        ("NO_COLOR".into(), "1".into()),
        ("TERM".into(), "dumb".into()),
        ("PYTHONIOENCODING".into(), "utf-8".into()),
        ("PYTHONDONTWRITEBYTECODE".into(), "1".into()),
        ("HOME".into(), home.to_string_lossy().into_owned()),
    ]
}

/// Read a structured report file without following a symlink and without exceeding
/// the bound. Returns `None` only when the file is absent; an over-limit or
/// non-regular file yields an `over_limit` artifact so the run is reported partial
/// while the raw output is still preserved as evidence.
pub fn capture_file(name: &str, path: &Path, cap: u64) -> Option<ExecutionArtifact> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file() {
        return Some(ExecutionArtifact {
            name: name.into(),
            bytes: Vec::new(),
            observed_bytes: None,
            over_limit: true,
        });
    }
    let observed = metadata.len();
    if observed > cap {
        return Some(ExecutionArtifact {
            name: name.into(),
            bytes: Vec::new(),
            observed_bytes: Some(observed),
            over_limit: true,
        });
    }
    let mut bytes = Vec::new();
    let file = std::fs::File::open(path).ok()?;
    file.take(cap + 1).read_to_end(&mut bytes).ok()?;
    let over_limit = bytes.len() as u64 > cap;
    if over_limit {
        bytes.clear();
    }
    Some(ExecutionArtifact {
        name: name.into(),
        bytes,
        observed_bytes: Some(observed),
        over_limit,
    })
}

/// Fetch a named captured report's bytes, mapping a missing or over-limit report to
/// a clear provider error (the raw output is still preserved separately as evidence).
pub fn report_bytes<'a>(
    execution: &'a super::Execution,
    name: &str,
    missing_message: &str,
) -> Result<&'a [u8]> {
    let artifact = execution
        .artifacts
        .iter()
        .find(|a| a.name == name)
        .ok_or_else(|| CoreError::new("ProviderFailure", missing_message))?;
    if artifact.over_limit {
        return Err(CoreError::new(
            "BudgetExceeded",
            "The provider report exceeded its size bound; raw output is preserved as evidence.",
        ));
    }
    Ok(&artifact.bytes)
}

/// Classify a version probe outcome into an [`Installation`]. A version that parses
/// and matches the reviewed series is `Installed`; a version the probe could not
/// parse is still `Installed` (the tool ran and exited cleanly) so a readable but
/// unlabeled build is usable; a clearly different series is `UnsupportedVersion`.
pub fn classify_version(
    version: Option<String>,
    series: &str,
    executable: PathBuf,
) -> Installation {
    match version {
        Some(version) if version.starts_with(series) => Installation::Installed {
            version,
            path: Some(executable),
        },
        None => Installation::Installed {
            version: "unknown".into(),
            path: Some(executable),
        },
        Some(version) => Installation::UnsupportedVersion { version },
    }
}
