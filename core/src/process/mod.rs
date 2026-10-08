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
        if let Some(path) = std::env::var_os("MACSPLOIT_NMAP") {
            overrides.insert("nmap".to_owned(), PathBuf::from(path));
        }
        if let Some(path) = std::env::var_os("MACSPLOIT_HTTPX") {
            overrides.insert("httpx".to_owned(), PathBuf::from(path));
        }
        if let Some(path) = std::env::var_os("MACSPLOIT_KATANA") {
            overrides.insert("katana".to_owned(), PathBuf::from(path));
        }
        if let Some(path) = std::env::var_os("MACSPLOIT_FFUF") {
            overrides.insert("ffuf".to_owned(), PathBuf::from(path));
        }
        // OSINT: user-scanner (pipx/pip console script `user-scanner`).
        if let Some(path) = std::env::var_os("MACSPLOIT_USER_SCANNER") {
            overrides.insert("user-scanner".to_owned(), PathBuf::from(path));
        }
        // Homebrew executable override (tests inject a fake brew; advanced users may pin).
        if let Some(path) = std::env::var_os("MACSPLOIT_BREW") {
            overrides.insert("brew".to_owned(), PathBuf::from(path));
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
    // Resolve the full symlink chain to a canonical path before accepting it. Homebrew
    // links CLI tools under /opt/homebrew/bin and /usr/local/bin as symlinks into the
    // Cellar, so rejecting symlinks outright would report brew-installed providers as
    // missing. canonicalize fails closed on a broken link, a symlink loop, or any
    // missing component, and never executes a shell. We then require the resolved
    // target to be a regular, executable file and return that canonical path.
    let resolved = std::fs::canonicalize(path).ok()?;
    let metadata = std::fs::metadata(&resolved).ok()?;
    if !metadata.is_file() {
        return None; // e.g. a symlink that points at a directory
    }
    if metadata.permissions().mode() & 0o111 == 0 {
        return None; // resolved target is not executable
    }
    Some(resolved)
}

/// Installation state of an external provider tool, surfaced to the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Installation {
    /// A native, always-available provider that runs no external tool.
    BuiltIn,
    Installed {
        version: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<PathBuf>,
    },
    Missing,
    UnsupportedVersion {
        version: String,
    },
    ExecutionError {
        message: String,
    },
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
            // Accept two-or-more component versions (e.g. nmap "7.95",
            // subfinder "2.6.6"); require at least one dot to avoid bare integers.
            if dots >= 1 && !token.ends_with('.') {
                return Some(token.to_owned());
            }
        } else {
            index += 1;
        }
    }
    None
}

/// Optional per-process settings for [`run_with`]. Environment entries are literal
/// key/value pairs set on the child (never expanded by a shell); `current_dir`
/// pins the child's working directory (e.g. a private per-run temporary directory).
#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    pub env: Vec<(String, String)>,
    pub current_dir: Option<PathBuf>,
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
    run_with(
        executable,
        args,
        cancelled,
        deadline,
        stdout_cap,
        stderr_cap,
        &RunOptions::default(),
    )
}

/// [`run`] with explicit environment additions and working directory.
pub fn run_with(
    executable: &Path,
    args: &[String],
    cancelled: &AtomicBool,
    deadline: Instant,
    stdout_cap: usize,
    stderr_cap: usize,
    options: &RunOptions,
) -> Result<ProcessOutcome> {
    let started_at = crate::now();
    let mut command = Command::new(executable);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in &options.env {
        command.env(key, value);
    }
    if let Some(directory) = &options.current_dir {
        command.current_dir(directory);
    }
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
    // Bytes past the cap are drained and discarded so a chatty tool never blocks on
    // a full pipe (which would otherwise stall it until the deadline).
    let stdout_handle = child
        .stdout
        .take()
        .map(|stream| thread::spawn(move || read_bounded(stream, stdout_cap)));
    let stderr_handle = child
        .stderr
        .take()
        .map(|stream| thread::spawn(move || read_bounded(stream, stderr_cap)));

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

    let stdout = stdout_handle
        .and_then(|h| h.join().ok())
        .unwrap_or_default();
    let stderr = stderr_handle
        .and_then(|h| h.join().ok())
        .unwrap_or_default();
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

/// Read at most `cap` bytes, then drain (and discard) the rest until EOF.
fn read_bounded(mut stream: impl Read, cap: usize) -> Vec<u8> {
    let mut buffer = Vec::new();
    let _ = (&mut stream).take(cap as u64).read_to_end(&mut buffer);
    let _ = std::io::copy(&mut stream, &mut std::io::sink());
    buffer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_version_finds_semver_token() {
        assert_eq!(
            scan_version("subfinder version v2.6.6").as_deref(),
            Some("2.6.6")
        );
        assert_eq!(scan_version("v1.10.0-dev").as_deref(), Some("1.10.0"));
        assert_eq!(
            scan_version("Nmap version 7.95 ( https://nmap.org )").as_deref(),
            Some("7.95")
        );
        assert_eq!(scan_version("no version here"), None);
        assert_eq!(scan_version("build 2026"), None);
    }

    #[test]
    fn locate_prefers_override_and_rejects_missing() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("faketool");
        std::fs::write(&script, "#!/bin/sh\necho hi\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut config = ToolConfig::default();
        config.overrides.insert("faketool".into(), script.clone());
        // locate returns the canonical path (temp dirs may sit under symlinked roots).
        assert_eq!(
            config.locate("faketool"),
            Some(script.canonicalize().unwrap())
        );
        assert_eq!(
            ToolConfig::default().locate("definitely-not-a-real-tool-xyz"),
            None
        );
    }

    fn write_exec(path: &Path) {
        std::fs::write(path, "#!/bin/sh\necho hi\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn locate_accepts_regular_executable_on_search_path() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let tool = bin.join("macsploit-faketool-xyz");
        write_exec(&tool);
        let mut config = ToolConfig::default();
        config.extra_paths.push(bin);
        assert_eq!(
            config.locate("macsploit-faketool-xyz"),
            Some(tool.canonicalize().unwrap())
        );
    }

    #[test]
    fn locate_resolves_homebrew_style_symlink_to_cellar() {
        // tmp/Cellar/nmap/7.99/bin/nmap  +  tmp/bin/nmap -> ../Cellar/nmap/7.99/bin/nmap
        let dir = tempfile::tempdir().unwrap();
        let cellar_bin = dir.path().join("Cellar/faketool/7.99/bin");
        std::fs::create_dir_all(&cellar_bin).unwrap();
        let real = cellar_bin.join("macsploit-cellartool-xyz");
        write_exec(&real);
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let link = bin.join("macsploit-cellartool-xyz");
        std::os::unix::fs::symlink(
            "../Cellar/faketool/7.99/bin/macsploit-cellartool-xyz",
            &link,
        )
        .unwrap();

        let mut config = ToolConfig::default();
        config.extra_paths.push(bin);
        // Discovery succeeds via the symlink and returns the resolved real executable.
        assert_eq!(
            config.locate("macsploit-cellartool-xyz"),
            Some(real.canonicalize().unwrap())
        );
    }

    #[test]
    fn usable_executable_rejects_broken_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("nmap");
        std::os::unix::fs::symlink(dir.path().join("missing-target"), &link).unwrap();
        assert_eq!(usable_executable(&link), None);
    }

    #[test]
    fn usable_executable_rejects_symlink_to_directory() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("somedir");
        std::fs::create_dir_all(&target).unwrap();
        let link = dir.path().join("nmap");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(usable_executable(&link), None);
    }

    #[test]
    fn usable_executable_rejects_symlink_to_non_executable_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("plain.txt");
        std::fs::write(&target, "data").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        let link = dir.path().join("nmap");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(usable_executable(&link), None);
    }

    #[test]
    fn usable_executable_rejects_symlink_loop() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::os::unix::fs::symlink(&b, &a).unwrap();
        std::os::unix::fs::symlink(&a, &b).unwrap();
        // canonicalize fails with ELOOP, so the candidate is rejected.
        assert_eq!(usable_executable(&a), None);
    }

    #[test]
    fn run_captures_output_and_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("emit");
        std::fs::write(
            &script,
            "#!/bin/sh\nprintf 'hello'\nprintf 'oops' 1>&2\nexit 3\n",
        )
        .unwrap();
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
    fn run_bounds_output_without_stalling_a_chatty_child() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("chatty");
        // ~1 MiB of output against a 1 KiB cap must still finish promptly.
        std::fs::write(
            &script,
            "#!/bin/sh\ni=0\nwhile [ $i -lt 16384 ]; do echo 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; i=$((i+1)); done\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let cancelled = AtomicBool::new(false);
        let outcome = run(
            &script,
            &[],
            &cancelled,
            Instant::now() + Duration::from_secs(20),
            1024,
            1024,
        )
        .unwrap();
        assert!(
            !outcome.timed_out,
            "bounded capture must not stall the child"
        );
        assert_eq!(outcome.exit_status, Some(0));
        assert_eq!(outcome.stdout.len(), 1024);
    }

    #[test]
    fn run_with_sets_environment_and_working_directory() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("envtool");
        std::fs::write(
            &script,
            "#!/bin/sh\nprintf '%s|' \"$MACSPLOIT_TEST_VALUE\"\npwd\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let work = tempfile::tempdir().unwrap();
        let cancelled = AtomicBool::new(false);
        let outcome = run_with(
            &script,
            &[],
            &cancelled,
            Instant::now() + Duration::from_secs(5),
            1024,
            1024,
            &RunOptions {
                env: vec![("MACSPLOIT_TEST_VALUE".into(), "$(id);literal".into())],
                current_dir: Some(work.path().to_path_buf()),
            },
        )
        .unwrap();
        let text = String::from_utf8(outcome.stdout).unwrap();
        let (value, cwd) = text.trim_end().split_once('|').unwrap();
        assert_eq!(
            value, "$(id);literal",
            "environment values are never shell-expanded"
        );
        assert_eq!(
            std::path::Path::new(cwd).canonicalize().unwrap(),
            work.path().canonicalize().unwrap()
        );
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
