//! Centralized, shell-free process supervision for external tool providers.
//!
//! Every real provider executes through [`run`], which spawns an executable with
//! an explicit argument array (never a shell), captures bounded stdout/stderr,
//! and enforces both a wall-clock deadline and cooperative cancellation. User
//! input is never interpreted as shell syntax: there is no `/bin/sh -c` path.

use crate::error::{CoreError, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io::Read,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

// Declared directly to avoid a `libc` dependency for two POSIX calls. `setsid`
// puts the child in its own session/process group; `killpg` then terminates the
// whole group so a killed tool cannot leave orphaned grandchildren holding pipes.
extern "C" {
    fn setsid() -> i32;
    fn killpg(pgrp: i32, sig: i32) -> i32;
}
const SIGKILL: i32 = 9;

/// Result of one supervised process execution.
#[derive(Debug, Clone)]
pub struct ProcessOutcome {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_status: Option<i32>,
    pub pid: Option<u32>,
    pub timed_out: bool,
    pub cancelled: bool,
    pub started_at: String,
    pub ended_at: String,
}

/// Where MACSPLOIT looks for external tool executables.
///
/// `overrides` pins an exact path for a named tool (used by tests to inject a
/// fake executable and by advanced users to point at a specific build).
#[derive(Debug, Clone, Default)]
pub struct ToolConfig {
    pub overrides: HashMap<String, PathBuf>,
    pub extra_paths: Vec<PathBuf>,
    pub managed_dir: Option<PathBuf>,
}

impl ToolConfig {
    /// Build a configuration from the environment. `MACSPLOIT_<TOOL>` (uppercase)
    /// pins an executable path; `MACSPLOIT_TOOLS_DIR` names a managed directory.
    pub fn from_env() -> Self {
        let mut overrides = HashMap::new();
        if let Some(path) = std::env::var_os("MACSPLOIT_SUBFINDER") {
            overrides.insert("subfinder".to_owned(), PathBuf::from(path));
        }
        let managed_dir = std::env::var_os("MACSPLOIT_TOOLS_DIR").map(PathBuf::from);
        Self {
            overrides,
            extra_paths: Vec::new(),
            managed_dir,
        }
    }

    /// Locate a tool executable without executing it. Order: explicit override,
    /// then `PATH`, then common Homebrew/local locations, then the managed
    /// directory. Only regular, owner-executable files qualify; symlinks are
    /// rejected to avoid surprising indirection.
    pub fn locate(&self, tool: &str) -> Option<PathBuf> {
        if let Some(path) = self.overrides.get(tool) {
            return usable_executable(path);
        }
        let mut directories: Vec<PathBuf> = Vec::new();
        if let Some(path) = std::env::var_os("PATH") {
            directories.extend(std::env::split_paths(&path));
        }
        directories.extend(self.extra_paths.iter().cloned());
        directories.push(PathBuf::from("/opt/homebrew/bin"));
        directories.push(PathBuf::from("/usr/local/bin"));
        if let Some(managed) = &self.managed_dir {
            directories.push(managed.clone());
        }
        directories
            .into_iter()
            .find_map(|directory| usable_executable(&directory.join(tool)))
    }
}

fn usable_executable(path: &Path) -> Option<PathBuf> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    // Reject symlinks: the resolved target could point outside expected roots.
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return None;
    }
    if metadata.permissions().mode() & 0o111 == 0 {
        return None;
    }
    Some(path.to_path_buf())
}

/// Installation state of an external provider tool, surfaced to the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Installation {
    Installed { version: String },
    Missing,
    UnsupportedVersion { version: String },
    ExecutionError { message: String },
}

/// Extract a `MAJOR.MINOR.PATCH` (optionally longer) version token from tool
/// output without pulling in a regex dependency. Returns the first plausible
/// dotted-numeric run, e.g. `2.6.6` from `subfinder version v2.6.6`.
pub fn scan_version(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_digit() {
            let start = index;
            let mut dots = 0;
            while index < bytes.len() && (bytes[index].is_ascii_digit() || bytes[index] == b'.') {
                if bytes[index] == b'.' {
                    dots += 1;
                }
                index += 1;
            }
            let token = &text[start..index];
            if dots >= 2 && !token.ends_with('.') {
                return Some(token.to_owned());
            }
        } else {
            index += 1;
        }
    }
    None
}

/// Run `executable args...` under supervision. Never uses a shell. Captures at
/// most `stdout_cap`/`stderr_cap` bytes. Kills the child if `cancelled` is set
/// or `deadline` passes.
pub fn run(
    executable: &Path,
    args: &[String],
    cancelled: &AtomicBool,
    deadline: Instant,
    stdout_cap: usize,
    stderr_cap: usize,
) -> Result<ProcessOutcome> {
    let started_at = crate::now();
    let mut command = Command::new(executable);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Run the child as its own process-group leader so the supervisor can kill
    // the entire group (tool plus any helpers it spawns), not just the direct
    // child. Safe: `setsid` is async-signal-safe and touches no Rust state.
    unsafe {
        command.pre_exec(|| {
            if setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|error| {
        CoreError::new(
            "ProviderFailure",
            &format!("Failed to launch the provider process: {error}"),
        )
    })?;
    let pid = child.id();
    // After `setsid`, the child's process-group id equals its pid.
    let kill_group = || unsafe {
        let _ = killpg(pid as i32, SIGKILL);
    };
    let pid = Some(pid);

    // Drain stdout/stderr on dedicated threads so a full pipe cannot deadlock
    // the supervisor loop. `take` bounds memory regardless of tool behavior.
    let stdout_handle = child.stdout.take().map(|stream| {
        thread::spawn(move || {
            let mut buffer = Vec::new();
            let _ = stream.take(stdout_cap as u64).read_to_end(&mut buffer);
            buffer
        })
    });
    let stderr_handle = child.stderr.take().map(|stream| {
        thread::spawn(move || {
            let mut buffer = Vec::new();
            let _ = stream.take(stderr_cap as u64).read_to_end(&mut buffer);
            buffer
        })
    });

    let mut timed_out = false;
    let mut was_cancelled = false;
    let status = loop {
        match child.try_wait()? {
            Some(status) => break Some(status),
            None => {
                if cancelled.load(Ordering::SeqCst) {
                    was_cancelled = true;
                    kill_group();
                    let _ = child.wait();
                    break None;
                }
                if Instant::now() >= deadline {
                    timed_out = true;
                    kill_group();
                    let _ = child.wait();
                    break None;
                }
                thread::sleep(Duration::from_millis(15));
            }
        }
    };

    let stdout = stdout_handle.and_then(|h| h.join().ok()).unwrap_or_default();
    let stderr = stderr_handle.and_then(|h| h.join().ok()).unwrap_or_default();
    Ok(ProcessOutcome {
        stdout,
        stderr,
        exit_status: status.and_then(|s| s.code()),
        pid,
        timed_out,
        cancelled: was_cancelled,
        started_at,
        ended_at: crate::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_version_finds_semver_token() {
        assert_eq!(scan_version("subfinder version v2.6.6").as_deref(), Some("2.6.6"));
        assert_eq!(scan_version("v1.10.0-dev").as_deref(), Some("1.10.0"));
        assert_eq!(scan_version("no version here"), None);
        assert_eq!(scan_version("only 1.2 minor"), None);
    }

    #[test]
    fn locate_prefers_override_and_rejects_missing() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("faketool");
        std::fs::write(&script, "#!/bin/sh\necho hi\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut config = ToolConfig::default();
        config.overrides.insert("faketool".into(), script.clone());
        assert_eq!(config.locate("faketool"), Some(script));
        assert_eq!(ToolConfig::default().locate("definitely-not-a-real-tool-xyz"), None);
    }

    #[test]
    fn run_captures_output_and_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("emit");
        std::fs::write(&script, "#!/bin/sh\nprintf 'hello'\nprintf 'oops' 1>&2\nexit 3\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let cancelled = AtomicBool::new(false);
        let outcome = run(
            &script,
            &[],
            &cancelled,
            Instant::now() + Duration::from_secs(5),
            1024,
            1024,
        )
        .unwrap();
        assert_eq!(outcome.stdout, b"hello");
        assert_eq!(outcome.stderr, b"oops");
        assert_eq!(outcome.exit_status, Some(3));
        assert!(!outcome.timed_out && !outcome.cancelled);
    }

    #[test]
    fn run_enforces_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("hang");
        std::fs::write(&script, "#!/bin/sh\nsleep 30\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let cancelled = AtomicBool::new(false);
        let outcome = run(
            &script,
            &[],
            &cancelled,
            Instant::now() + Duration::from_millis(150),
            1024,
            1024,
        )
        .unwrap();
        assert!(outcome.timed_out);
        assert_ne!(outcome.exit_status, Some(0));
    }

    #[test]
    fn run_honors_cancellation() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("hang2");
        std::fs::write(&script, "#!/bin/sh\nsleep 30\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let cancelled = std::sync::Arc::new(AtomicBool::new(false));
        let flag = cancelled.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(80));
            flag.store(true, Ordering::SeqCst);
        });
        let outcome = run(
            &script,
            &[],
            &cancelled,
            Instant::now() + Duration::from_secs(10),
            1024,
            1024,
        )
        .unwrap();
        assert!(outcome.cancelled);
    }
}
