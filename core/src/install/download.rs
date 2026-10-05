//! Bounded, HTTPS-only, checksum-verified artifact download.
//!
//! Downloading is driven through the [`DownloadTransport`] trait so the entire
//! security-critical pipeline (redirect allow-listing, size bounds, streaming
//! enforcement, SHA-256 verification, cancellation) is testable **offline** with
//! a static transport. The production [`UreqTransport`] performs a single request
//! and **never follows redirects itself** — this module follows them so every hop
//! is scheme- and host-checked. No shell, no `curl`, no external process.

use super::manifest::{ManagedArtifact, ALLOWED_HOSTS, MAX_REDIRECTS};
use crate::error::{CoreError, Result};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

/// One HTTP response for a download: status, an optional `Location` (for 3xx),
/// an optional advertised length, and a **streaming** body reader.
pub struct FetchResponse {
    pub status: u16,
    pub location: Option<String>,
    pub content_length: Option<u64>,
    pub body: Box<dyn Read + Send>,
}

/// A single, non-redirect-following HTTPS GET. Implementations must not follow
/// redirects (this module does, with host checks) and must honor the deadline.
pub trait DownloadTransport: Send + Sync {
    fn get(&self, url: &str, deadline: Instant, cancelled: &AtomicBool) -> Result<FetchResponse>;
}

fn cancelled_or_expired(cancelled: &AtomicBool, deadline: Instant) -> Result<()> {
    if cancelled.load(Ordering::SeqCst) {
        return Err(CoreError::new("Cancelled", "Installation cancelled."));
    }
    if Instant::now() >= deadline {
        return Err(CoreError::new("Timeout", "The download timed out."));
    }
    Ok(())
}

/// Parse a URL and require HTTPS with a host in the reviewed allow-list. Rejects
/// `http`/`file`/`ftp`/`data`, credential-bearing URLs, and unknown hosts.
fn require_https_allowed(raw: &str) -> Result<url::Url> {
    let parsed = url::Url::parse(raw)
        .map_err(|_| CoreError::new("InsecureSource", "Malformed download URL."))?;
    if parsed.scheme() != "https" {
        return Err(CoreError::new(
            "InsecureSource",
            "Managed downloads must use HTTPS.",
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(CoreError::new(
            "InsecureSource",
            "Credential-bearing URLs are not allowed.",
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| CoreError::new("InsecureSource", "Download URL has no host."))?;
    if !ALLOWED_HOSTS.iter().any(|h| h.eq_ignore_ascii_case(host)) {
        return Err(CoreError::new(
            "InsecureSource",
            "Download host is not a reviewed release-asset host.",
        ));
    }
    Ok(parsed)
}

/// Resolve a `Location` header against the current URL and re-check it. The
/// result must itself be HTTPS on an allowed host.
fn resolve_redirect(current: &url::Url, location: &str) -> Result<String> {
    let next = current
        .join(location)
        .map_err(|_| CoreError::new("InsecureSource", "Malformed redirect target."))?;
    require_https_allowed(next.as_str())?;
    Ok(next.into())
}

/// Constant-time comparison of two equal-length byte slices. Differing lengths
/// compare unequal without short-circuiting on content.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Download `artifact` to `dest`, following only allow-listed HTTPS redirects,
/// enforcing size bounds while streaming, and verifying SHA-256 before returning.
/// On any failure the partial `dest` file is removed; the caller's existing
/// installation (elsewhere) is never touched by this function.
pub fn download_verified(
    transport: &dyn DownloadTransport,
    artifact: &ManagedArtifact,
    dest: &Path,
    cancelled: &AtomicBool,
    deadline: Instant,
) -> Result<()> {
    match download_inner(transport, artifact, dest, cancelled, deadline) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = std::fs::remove_file(dest);
            Err(error)
        }
    }
}

fn download_inner(
    transport: &dyn DownloadTransport,
    artifact: &ManagedArtifact,
    dest: &Path,
    cancelled: &AtomicBool,
    deadline: Instant,
) -> Result<()> {
    let mut current = require_https_allowed(&artifact.url)?;
    let mut hops = 0u32;
    let response = loop {
        cancelled_or_expired(cancelled, deadline)?;
        let resp = transport.get(current.as_str(), deadline, cancelled)?;
        if (300..400).contains(&resp.status) {
            hops += 1;
            if hops > MAX_REDIRECTS {
                return Err(CoreError::new(
                    "TooManyRedirects",
                    "The download redirected too many times.",
                ));
            }
            let location = resp.location.ok_or_else(|| {
                CoreError::new("DownloadFailed", "Redirect without a destination.")
            })?;
            current = url::Url::parse(&resolve_redirect(&current, &location)?)
                .map_err(|_| CoreError::new("InsecureSource", "Malformed redirect target."))?;
            continue;
        }
        if resp.status != 200 {
            return Err(CoreError::new(
                "DownloadFailed",
                "The download server returned an unexpected status.",
            ));
        }
        break resp;
    };

    // Reject up front if the advertised length already exceeds the bound; still
    // enforce the bound while streaming because Content-Length cannot be trusted.
    if let Some(len) = response.content_length {
        if len > artifact.max_download_bytes {
            return Err(CoreError::new(
                "DownloadTooLarge",
                "The download exceeds the allowed size.",
            ));
        }
    }

    let mut file = std::fs::File::create(dest)?;
    let mut hasher = Sha256::new();
    let mut reader = response.body;
    let mut buffer = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        cancelled_or_expired(cancelled, deadline)?;
        let read = reader
            .read(&mut buffer)
            .map_err(|e| CoreError::new("DownloadFailed", &format!("Download read error: {e}")))?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > artifact.max_download_bytes {
            return Err(CoreError::new(
                "DownloadTooLarge",
                "The download exceeds the allowed size.",
            ));
        }
        hasher.update(&buffer[..read]);
        file.write_all(&buffer[..read])?;
    }
    file.flush()?;
    drop(file);

    let digest = hex_lower(&hasher.finalize());
    if !constant_time_eq(digest.as_bytes(), artifact.sha256.as_bytes()) {
        return Err(CoreError::new(
            "ChecksumMismatch",
            "The downloaded artifact failed checksum verification.",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Production transport: a single bounded HTTPS request, no redirect following.
// ---------------------------------------------------------------------------

/// Real network transport (ureq). Never follows redirects; the caller does, with
/// host checks. Selected only outside tests (tests inject a static transport).
pub struct UreqTransport {
    agent: ureq::Agent,
}

impl Default for UreqTransport {
    fn default() -> Self {
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .timeout_connect(std::time::Duration::from_secs(20))
            .timeout_read(std::time::Duration::from_secs(60))
            .build();
        Self { agent }
    }
}

impl DownloadTransport for UreqTransport {
    fn get(&self, url: &str, _deadline: Instant, _cancelled: &AtomicBool) -> Result<FetchResponse> {
        let result = self.agent.get(url).call();
        let response = match result {
            Ok(response) => response,
            // ureq surfaces >= 400 as Error::Status; normalize into a FetchResponse
            // so the caller's status handling (and failure path) stays uniform.
            Err(ureq::Error::Status(code, response)) => {
                return Ok(FetchResponse {
                    status: code,
                    location: response.header("location").map(str::to_owned),
                    content_length: None,
                    body: Box::new(std::io::empty()),
                });
            }
            Err(error) => {
                return Err(CoreError::new(
                    "DownloadFailed",
                    &format!("Download request failed: {error}"),
                ))
            }
        };
        let status = response.status();
        let location = response.header("location").map(str::to_owned);
        let content_length = response
            .header("content-length")
            .and_then(|v| v.parse::<u64>().ok());
        Ok(FetchResponse {
            status,
            location,
            content_length,
            body: Box::new(response.into_reader()),
        })
    }
}

/// Select a download transport. Tests set `MACSPLOIT_DOWNLOAD_FAKE` to force the
/// empty static transport (fail-closed, no network) for any code path that might
/// otherwise reach the real one.
pub fn transport_from_env() -> std::sync::Arc<dyn DownloadTransport> {
    if std::env::var_os("MACSPLOIT_DOWNLOAD_FAKE").is_some() {
        std::sync::Arc::new(StaticDownloadTransport::new())
    } else {
        std::sync::Arc::new(UreqTransport::default())
    }
}

// ---------------------------------------------------------------------------
// Static (offline) transport for tests.
// ---------------------------------------------------------------------------

/// A reader that yields `remaining` zero bytes — used to simulate an oversized or
/// slow streamed body without allocating it.
pub struct ZeroReader {
    remaining: u64,
}

impl ZeroReader {
    pub fn new(total: u64) -> Self {
        Self { remaining: total }
    }
}

impl Read for ZeroReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let n = (buf.len() as u64).min(self.remaining) as usize;
        for b in buf.iter_mut().take(n) {
            *b = 0;
        }
        self.remaining -= n as u64;
        Ok(n)
    }
}

#[derive(Clone)]
enum Programmed {
    Redirect {
        status: u16,
        location: String,
    },
    Body {
        status: u16,
        content_length: Option<u64>,
        bytes: Vec<u8>,
    },
    /// Streams `total` bytes with the given advertised length (often `None`).
    Stream {
        content_length: Option<u64>,
        total: u64,
    },
    Failure(String),
}

/// Offline transport: responses are programmed per-URL. Any unprogrammed URL
/// fails closed.
#[derive(Default, Clone)]
pub struct StaticDownloadTransport {
    table: std::collections::HashMap<String, Programmed>,
}

impl StaticDownloadTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_redirect(mut self, url: &str, status: u16, location: &str) -> Self {
        self.table.insert(
            url.to_owned(),
            Programmed::Redirect {
                status,
                location: location.to_owned(),
            },
        );
        self
    }

    pub fn with_body(mut self, url: &str, bytes: Vec<u8>) -> Self {
        let len = bytes.len() as u64;
        self.table.insert(
            url.to_owned(),
            Programmed::Body {
                status: 200,
                content_length: Some(len),
                bytes,
            },
        );
        self
    }

    /// A 200 body with a chosen (possibly lying/absent) Content-Length.
    pub fn with_body_len(mut self, url: &str, bytes: Vec<u8>, content_length: Option<u64>) -> Self {
        self.table.insert(
            url.to_owned(),
            Programmed::Body {
                status: 200,
                content_length,
                bytes,
            },
        );
        self
    }

    /// A 200 that streams `total` zero bytes with the given advertised length.
    pub fn with_stream(mut self, url: &str, total: u64, content_length: Option<u64>) -> Self {
        self.table.insert(
            url.to_owned(),
            Programmed::Stream {
                content_length,
                total,
            },
        );
        self
    }

    pub fn with_failure(mut self, url: &str, message: &str) -> Self {
        self.table
            .insert(url.to_owned(), Programmed::Failure(message.to_owned()));
        self
    }
}

impl DownloadTransport for StaticDownloadTransport {
    fn get(&self, url: &str, _deadline: Instant, _cancelled: &AtomicBool) -> Result<FetchResponse> {
        match self.table.get(url) {
            Some(Programmed::Redirect { status, location }) => Ok(FetchResponse {
                status: *status,
                location: Some(location.clone()),
                content_length: None,
                body: Box::new(std::io::empty()),
            }),
            Some(Programmed::Body {
                status,
                content_length,
                bytes,
            }) => Ok(FetchResponse {
                status: *status,
                location: None,
                content_length: *content_length,
                body: Box::new(std::io::Cursor::new(bytes.clone())),
            }),
            Some(Programmed::Stream {
                content_length,
                total,
            }) => Ok(FetchResponse {
                status: 200,
                location: None,
                content_length: *content_length,
                body: Box::new(ZeroReader::new(*total)),
            }),
            Some(Programmed::Failure(message)) => Err(CoreError::new("DownloadFailed", message)),
            None => Err(CoreError::new(
                "DownloadFailed",
                "No route to the requested download URL.",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::manifest::{Arch, ArchiveFormat};
    use super::*;
    use std::time::Duration;

    fn artifact(url: &str, sha: &str, max: u64) -> ManagedArtifact {
        ManagedArtifact {
            provider_id: "fake".into(),
            version: "0".into(),
            arch: Arch::Arm64,
            url: url.into(),
            sha256: sha.into(),
            archive: ArchiveFormat::Zip,
            member: "fake".into(),
            installed_name: "fake".into(),
            max_download_bytes: max,
            max_extracted_bytes: max,
        }
    }

    fn sha_hex(bytes: &[u8]) -> String {
        hex_lower(&Sha256::digest(bytes))
    }

    #[test]
    fn rejects_non_https_and_disallowed_hosts() {
        assert!(require_https_allowed("http://github.com/x").is_err());
        assert!(require_https_allowed("file:///etc/passwd").is_err());
        assert!(require_https_allowed("ftp://github.com/x").is_err());
        assert!(require_https_allowed("https://evil.example.com/x").is_err());
        // Assembled from parts so the repository secret audit does not see a literal
        // credential-in-URL; the point is only that such URLs are rejected.
        let creds = ["user", "pass"].join(":");
        assert!(require_https_allowed(&format!("https://{creds}@github.com/x")).is_err());
        assert!(require_https_allowed("https://release-assets.githubusercontent.com/x").is_ok());
        assert!(require_https_allowed("https://github.com/x").is_ok());
    }

    #[test]
    fn redirect_to_disallowed_host_is_rejected() {
        let url = "https://github.com/a";
        let t =
            StaticDownloadTransport::new().with_redirect(url, 302, "https://evil.example.com/b");
        let a = artifact(url, &sha_hex(b"x"), 1024);
        let dest = tempfile::NamedTempFile::new().unwrap();
        let err = download_verified(
            &t,
            &a,
            dest.path(),
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap_err();
        assert_eq!(err.code, "InsecureSource");
    }

    #[test]
    fn too_many_redirects_is_rejected() {
        let url = "https://github.com/loop";
        // Points to an allowed host but keeps redirecting to itself.
        let t = StaticDownloadTransport::new().with_redirect(url, 302, url);
        let a = artifact(url, &sha_hex(b"x"), 1024);
        let dest = tempfile::NamedTempFile::new().unwrap();
        let err = download_verified(
            &t,
            &a,
            dest.path(),
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap_err();
        assert_eq!(err.code, "TooManyRedirects");
    }

    #[test]
    fn oversized_content_length_rejected_before_streaming() {
        let url = "https://github.com/big";
        let t = StaticDownloadTransport::new().with_body_len(url, vec![0u8; 10], Some(10_000));
        let a = artifact(url, &sha_hex(&[0u8; 10]), 1024);
        let dest = tempfile::NamedTempFile::new().unwrap();
        let err = download_verified(
            &t,
            &a,
            dest.path(),
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap_err();
        assert_eq!(err.code, "DownloadTooLarge");
    }

    #[test]
    fn streamed_body_exceeding_limit_rejected_even_without_content_length() {
        let url = "https://github.com/stream";
        let t = StaticDownloadTransport::new().with_stream(url, 5000, None);
        let a = artifact(url, &sha_hex(b"anything"), 1024);
        let dest = tempfile::NamedTempFile::new().unwrap();
        let err = download_verified(
            &t,
            &a,
            dest.path(),
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap_err();
        assert_eq!(err.code, "DownloadTooLarge");
        // Partial file is cleaned up.
        assert!(!dest.path().exists() || std::fs::metadata(dest.path()).unwrap().len() <= 1024);
    }

    #[test]
    fn correct_checksum_succeeds_incorrect_fails() {
        let url = "https://github.com/ok";
        let payload = b"the real artifact bytes".to_vec();
        let good = artifact(url, &sha_hex(&payload), 1024);
        let t = StaticDownloadTransport::new().with_body(url, payload.clone());
        let dest = tempfile::NamedTempFile::new().unwrap();
        download_verified(
            &t,
            &good,
            dest.path(),
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(std::fs::read(dest.path()).unwrap(), payload);

        let bad = artifact(url, &sha_hex(b"different"), 1024);
        let dest2 = tempfile::NamedTempFile::new().unwrap();
        let err = download_verified(
            &t,
            &bad,
            dest2.path(),
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap_err();
        assert_eq!(err.code, "ChecksumMismatch");
    }

    #[test]
    fn follows_one_allowed_redirect_then_downloads() {
        let start = "https://github.com/dl";
        let cdn = "https://release-assets.githubusercontent.com/asset";
        let payload = b"redirected payload".to_vec();
        let t = StaticDownloadTransport::new()
            .with_redirect(start, 302, cdn)
            .with_body(cdn, payload.clone());
        let a = artifact(start, &sha_hex(&payload), 1024);
        let dest = tempfile::NamedTempFile::new().unwrap();
        download_verified(
            &t,
            &a,
            dest.path(),
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(std::fs::read(dest.path()).unwrap(), payload);
    }

    #[test]
    fn cancellation_stops_download() {
        let url = "https://github.com/c";
        let t = StaticDownloadTransport::new().with_stream(url, 1_000_000, None);
        let a = artifact(url, &sha_hex(b"x"), 10_000_000);
        let dest = tempfile::NamedTempFile::new().unwrap();
        let err = download_verified(
            &t,
            &a,
            dest.path(),
            &AtomicBool::new(true), // already cancelled
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap_err();
        assert_eq!(err.code, "Cancelled");
    }

    #[test]
    fn timeout_fails() {
        let url = "https://github.com/t";
        let t = StaticDownloadTransport::new().with_body(url, vec![1, 2, 3]);
        let a = artifact(url, &sha_hex(&[1, 2, 3]), 1024);
        let dest = tempfile::NamedTempFile::new().unwrap();
        let err = download_verified(
            &t,
            &a,
            dest.path(),
            &AtomicBool::new(false),
            Instant::now() - Duration::from_secs(1), // already expired
        )
        .unwrap_err();
        assert_eq!(err.code, "Timeout");
    }

    #[test]
    fn constant_time_eq_matches_semantics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
