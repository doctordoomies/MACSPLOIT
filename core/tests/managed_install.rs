//! End-to-end managed-install pipeline coverage (download → verify → extract →
//! atomic install → discovery), run entirely offline with a static transport and
//! fixture archives. Exercises the exact `install_managed_artifact` logic the
//! engine uses in production; only the transport and the artifact are injected.

use macsploit_core::install::download::StaticDownloadTransport;
use macsploit_core::install::install_managed_artifact;
use macsploit_core::install::manifest::{Arch, ArchiveFormat, ManagedArtifact};
use macsploit_core::process::ToolConfig;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

fn sha_hex(bytes: &[u8]) -> String {
    let mut s = String::new();
    for b in Sha256::digest(bytes) {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A minimal zip archive containing a top-level `member` file plus benign junk.
fn make_zip(member: &str, body: &[u8]) -> Vec<u8> {
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut w = zip::ZipWriter::new(&mut cursor);
        let opts = zip::write::FileOptions::<()>::default().unix_permissions(0o755);
        w.start_file(member, opts).unwrap();
        w.write_all(body).unwrap();
        w.start_file("LICENSE.md", opts).unwrap();
        w.write_all(b"license").unwrap();
        w.finish().unwrap();
    }
    cursor.into_inner()
}

fn fixture_artifact(url: &str, archive_bytes: &[u8], member: &str) -> ManagedArtifact {
    ManagedArtifact {
        provider_id: member.into(),
        version: "9.9.9".into(),
        arch: Arch::host().unwrap_or(Arch::Arm64),
        url: url.into(),
        sha256: sha_hex(archive_bytes),
        archive: ArchiveFormat::Zip,
        member: member.into(),
        installed_name: member.into(),
        max_download_bytes: 1024 * 1024,
        max_extracted_bytes: 1024 * 1024,
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

#[test]
fn managed_install_downloads_verifies_extracts_and_installs() {
    let dir = tempfile::tempdir().unwrap();
    let managed = dir.path().join("Providers");
    // A unique name that cannot already exist on PATH, so discovery unambiguously
    // resolves to the managed directory on any dev/CI machine.
    let name = "macsploit-managedtest-xyz";
    let url = "https://github.com/x/releases/download/v9/tool.zip";
    let body = b"#!/bin/sh\necho tool\n";
    let archive = make_zip(name, body);
    let artifact = fixture_artifact(url, &archive, name);
    let transport = StaticDownloadTransport::new().with_body(url, archive.clone());

    let installed = install_managed_artifact(
        &transport,
        &artifact,
        &managed,
        &AtomicBool::new(false),
        deadline(),
    )
    .unwrap();

    assert_eq!(installed, managed.join(name));
    assert_eq!(std::fs::read(&installed).unwrap(), body);
    // Regular file, executable, and NOT a symlink.
    let meta = std::fs::symlink_metadata(&installed).unwrap();
    assert!(meta.file_type().is_file());
    assert!(meta.permissions().mode() & 0o111 != 0);

    // Discovery: the normal ToolConfig locate() finds the managed executable.
    let tools = ToolConfig {
        managed_dir: Some(managed.clone()),
        ..Default::default()
    };
    assert_eq!(tools.locate(name), Some(installed.canonicalize().unwrap()));
}

#[test]
fn managed_install_follows_allowed_redirect() {
    let dir = tempfile::tempdir().unwrap();
    let managed = dir.path().join("Providers");
    let start = "https://github.com/x/releases/download/v9/httpx.zip";
    let cdn = "https://release-assets.githubusercontent.com/httpx-asset";
    let body = b"HTTPXBIN";
    let archive = make_zip("httpx", body);
    let artifact = fixture_artifact(start, &archive, "httpx");
    let transport = StaticDownloadTransport::new()
        .with_redirect(start, 302, cdn)
        .with_body(cdn, archive);

    let installed = install_managed_artifact(
        &transport,
        &artifact,
        &managed,
        &AtomicBool::new(false),
        deadline(),
    )
    .unwrap();
    assert_eq!(std::fs::read(&installed).unwrap(), body);
}

fn preexisting(managed: &Path, name: &str, body: &[u8]) {
    std::fs::create_dir_all(managed).unwrap();
    let p = managed.join(name);
    std::fs::write(&p, body).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn checksum_mismatch_fails_and_preserves_previous_binary() {
    let dir = tempfile::tempdir().unwrap();
    let managed = dir.path().join("Providers");
    let good = b"PREVIOUS-GOOD-BINARY";
    preexisting(&managed, "subfinder", good);

    let url = "https://github.com/x/releases/download/v9/subfinder.zip";
    let archive = make_zip("subfinder", b"new");
    let mut artifact = fixture_artifact(url, &archive, "subfinder");
    // Corrupt the pinned digest so verification must fail.
    artifact.sha256 = "0".repeat(64);
    let transport = StaticDownloadTransport::new().with_body(url, archive);

    let err = install_managed_artifact(
        &transport,
        &artifact,
        &managed,
        &AtomicBool::new(false),
        deadline(),
    )
    .unwrap_err();
    assert_eq!(err.code, "ChecksumMismatch");
    // Previous good binary is untouched.
    assert_eq!(std::fs::read(managed.join("subfinder")).unwrap(), good);
}

#[test]
fn extraction_failure_preserves_previous_binary() {
    let dir = tempfile::tempdir().unwrap();
    let managed = dir.path().join("Providers");
    let good = b"PREVIOUS-GOOD";
    preexisting(&managed, "subfinder", good);

    let url = "https://github.com/x/releases/download/v9/subfinder.zip";
    // Archive's checksum matches, but it does not contain the expected member.
    let archive = make_zip("not-subfinder", b"x");
    let artifact = fixture_artifact(url, &archive, "subfinder");
    let transport = StaticDownloadTransport::new().with_body(url, archive);

    let err = install_managed_artifact(
        &transport,
        &artifact,
        &managed,
        &AtomicBool::new(false),
        deadline(),
    )
    .unwrap_err();
    assert_eq!(err.code, "UnsafeArchive");
    assert_eq!(std::fs::read(managed.join("subfinder")).unwrap(), good);
}

#[test]
fn cancellation_fails_and_preserves_previous_binary() {
    let dir = tempfile::tempdir().unwrap();
    let managed = dir.path().join("Providers");
    let good = b"PREVIOUS-GOOD";
    preexisting(&managed, "subfinder", good);

    let url = "https://github.com/x/releases/download/v9/subfinder.zip";
    let archive = make_zip("subfinder", b"new-binary");
    let artifact = fixture_artifact(url, &archive, "subfinder");
    let transport = StaticDownloadTransport::new().with_body(url, archive);

    let err = install_managed_artifact(
        &transport,
        &artifact,
        &managed,
        &AtomicBool::new(true), // cancelled before it starts
        deadline(),
    )
    .unwrap_err();
    assert_eq!(err.code, "Cancelled");
    assert_eq!(std::fs::read(managed.join("subfinder")).unwrap(), good);
}

/// Manual acceptance only (network): downloads the real pinned ffuf release for the
/// host architecture into a throwaway temp directory, verifies it, installs it, and
/// runs `-V`. Never touches the user's real tools or any system directory. Excluded
/// from the automated suite; run with `cargo test -p macsploit-core --test
/// managed_install -- --ignored`.
#[test]
#[ignore = "network: downloads a real pinned release into a temp dir; run manually"]
fn real_managed_install_ffuf_from_upstream() {
    let arch = Arch::host().expect("supported host architecture");
    let artifact = macsploit_core::install::manifest::artifact("ffuf", arch).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let managed = dir.path().join("Providers");
    let transport = macsploit_core::install::download::UreqTransport::default();
    let installed = install_managed_artifact(
        &transport,
        &artifact,
        &managed,
        &AtomicBool::new(false),
        Instant::now() + Duration::from_secs(120),
    )
    .expect("real managed install should succeed");
    assert_eq!(installed, managed.join("ffuf"));
    let meta = std::fs::symlink_metadata(&installed).unwrap();
    assert!(meta.file_type().is_file());
    assert!(meta.permissions().mode() & 0o111 != 0);
    let output = std::process::Command::new(&installed)
        .arg("-V")
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("2.3.0"), "ffuf -V output: {text}");
}

#[test]
fn successful_update_replaces_previous_binary_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let managed = dir.path().join("Providers");
    preexisting(&managed, "subfinder", b"OLD");

    let url = "https://github.com/x/releases/download/v9/subfinder.zip";
    let body = b"NEW-VERSION";
    let archive = make_zip("subfinder", body);
    let artifact = fixture_artifact(url, &archive, "subfinder");
    let transport = StaticDownloadTransport::new().with_body(url, archive);

    install_managed_artifact(
        &transport,
        &artifact,
        &managed,
        &AtomicBool::new(false),
        deadline(),
    )
    .unwrap();
    assert_eq!(std::fs::read(managed.join("subfinder")).unwrap(), body);
    // No staging leftovers remain in the managed directory.
    let leftovers: Vec<_> = std::fs::read_dir(&managed)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".staging-"))
        .collect();
    assert!(leftovers.is_empty(), "staging dir not cleaned up");
}
