//! HTTP transport for the native web-analysis provider.
//!
//! Analysis logic (redirect following, scope checks, header/cookie/CORS/robots
//! normalization) lives in the provider and is driven through the [`WebTransport`]
//! trait so it is fully testable offline. The production [`UreqTransport`] performs
//! a single, bounded HTTP(S) request (it never follows redirects itself — the
//! provider follows them so every hop is scope-checked); [`StaticWebTransport`]
//! serves fixtures with no network access.

use crate::error::{CoreError, Result};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

/// One HTTP response as observed by MACSPLOIT. Headers preserve order and may
/// repeat (e.g. multiple `Set-Cookie`). Body is already byte-capped by the
/// transport.
#[derive(Debug, Clone, Default)]
pub struct WebResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl WebResponse {
    /// First header value matching `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    /// All header values matching `name` (case-insensitive), in order.
    pub fn header_all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

/// Synchronous, single-request HTTP transport. Implementations must honor the
/// deadline/cancellation, cap the body, and never follow redirects.
pub trait WebTransport: Send + Sync {
    fn fetch(&self, url: &str, deadline: Instant, cancelled: &AtomicBool) -> Result<WebResponse>;
    /// One bounded request whose body is read to at most `cap` bytes; the flag
    /// reports whether the body was longer than `cap` (and therefore cut). Used by
    /// the passive OSINT clients (RDAP, certificate transparency), which must
    /// detect an oversized response instead of parsing a silently truncated one.
    /// The whole remaining `deadline` applies (no per-request clamp).
    fn fetch_bounded(
        &self,
        url: &str,
        deadline: Instant,
        cancelled: &AtomicBool,
        cap: usize,
    ) -> Result<(WebResponse, bool)> {
        let mut response = self.fetch(url, deadline, cancelled)?;
        let truncated = response.body.len() > cap;
        response.body.truncate(cap);
        Ok((response, truncated))
    }
    fn built_in(&self) -> bool {
        true
    }
}

/// Maximum response body MACSPLOIT reads (robots.txt / minimal parsing needs).
pub const MAX_BODY_BYTES: usize = 256 * 1024;

/// Select a transport from the environment: `MACSPLOIT_WEB_FIXTURE` points at a
/// JSON fixture file for offline runs (used by the Swift bridge test); otherwise
/// the real network transport is used.
pub fn transport_from_env() -> Arc<dyn WebTransport> {
    if let Some(path) = std::env::var_os("MACSPLOIT_WEB_FIXTURE") {
        match StaticWebTransport::from_fixture_file(&path.to_string_lossy()) {
            Ok(transport) => Arc::new(transport),
            // Fail closed to an empty static transport rather than hitting the net.
            Err(_) => Arc::new(StaticWebTransport::new()),
        }
    } else {
        Arc::new(UreqTransport::default())
    }
}

// ---------------------------------------------------------------------------
// Static (offline) transport — all automated tests and the MACSPLOIT_WEB_FIXTURE
// override. No network activity.
// ---------------------------------------------------------------------------

#[derive(Clone)]
enum Programmed {
    Response(WebResponse),
    Timeout,
    Failure(String),
}

#[derive(Default, Clone)]
pub struct StaticWebTransport {
    table: HashMap<String, Programmed>,
}

impl StaticWebTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_response(
        mut self,
        url: &str,
        status: u16,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Self {
        self.table.insert(
            url.to_owned(),
            Programmed::Response(WebResponse {
                status,
                headers: headers
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect(),
                body: body.as_bytes().to_vec(),
            }),
        );
        self
    }

    pub fn with_timeout(mut self, url: &str) -> Self {
        self.table.insert(url.to_owned(), Programmed::Timeout);
        self
    }

    pub fn with_failure(mut self, url: &str, message: &str) -> Self {
        self.table
            .insert(url.to_owned(), Programmed::Failure(message.to_owned()));
        self
    }

    /// Parse a fixture file: a JSON object mapping URL -> {status, headers:{..}, body}.
    /// Headers with repeated values use an array. Unknown URLs 404 with no headers.
    pub fn from_fixture_file(path: &str) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let value: serde_json::Value = serde_json::from_str(&text)?;
        let mut transport = Self::new();
        if let Some(map) = value.as_object() {
            for (url, spec) in map {
                let status = spec.get("status").and_then(|s| s.as_u64()).unwrap_or(200) as u16;
                let body = spec.get("body").and_then(|b| b.as_str()).unwrap_or("");
                let mut headers = Vec::new();
                if let Some(hmap) = spec.get("headers").and_then(|h| h.as_object()) {
                    for (name, hv) in hmap {
                        match hv {
                            serde_json::Value::Array(items) => {
                                for item in items {
                                    if let Some(s) = item.as_str() {
                                        headers.push((name.clone(), s.to_owned()));
                                    }
                                }
                            }
                            serde_json::Value::String(s) => headers.push((name.clone(), s.clone())),
                            _ => {}
                        }
                    }
                }
                transport.table.insert(
                    url.clone(),
                    Programmed::Response(WebResponse {
                        status,
                        headers,
                        body: body.as_bytes().to_vec(),
                    }),
                );
            }
        }
        Ok(transport)
    }
}

impl WebTransport for StaticWebTransport {
    fn fetch(&self, url: &str, _deadline: Instant, cancelled: &AtomicBool) -> Result<WebResponse> {
        if cancelled.load(Ordering::SeqCst) {
            return Err(CoreError::new("Cancelled", "Web analysis cancelled."));
        }
        match self.table.get(url) {
            Some(Programmed::Response(response)) => Ok(response.clone()),
            Some(Programmed::Timeout) => {
                Err(CoreError::new("ProviderTimeout", "Request timed out."))
            }
            Some(Programmed::Failure(message)) => Err(CoreError::new("ProviderFailure", message)),
            None => Ok(WebResponse {
                status: 404,
                headers: Vec::new(),
                body: Vec::new(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Production transport — one bounded request via ureq, no redirect following,
// TLS validation left ON. Only used outside automated tests.
// ---------------------------------------------------------------------------

pub struct UreqTransport {
    body_cap: usize,
}

impl UreqTransport {
    /// One request with redirects disabled and HTTP statuses returned as responses.
    fn request(&self, url: &str, timeout: Duration) -> Result<ureq::http::Response<ureq::Body>> {
        let config = ureq::Agent::config_builder()
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_global(Some(timeout))
            .build();
        let agent = ureq::Agent::new_with_config(config);
        agent.get(url).call().map_err(|error| {
            CoreError::new("ProviderFailure", &format!("HTTP transport error: {error}"))
        })
    }

    fn headers(response: &ureq::http::Response<ureq::Body>) -> Vec<(String, String)> {
        response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect()
    }
}

impl Default for UreqTransport {
    fn default() -> Self {
        Self {
            body_cap: MAX_BODY_BYTES,
        }
    }
}

impl WebTransport for UreqTransport {
    fn fetch(&self, url: &str, deadline: Instant, cancelled: &AtomicBool) -> Result<WebResponse> {
        use std::io::Read;
        if cancelled.load(Ordering::SeqCst) {
            return Err(CoreError::new("Cancelled", "Web analysis cancelled."));
        }
        let budget = deadline.saturating_duration_since(Instant::now());
        if budget.is_zero() {
            return Err(CoreError::new(
                "ProviderTimeout",
                "Web analysis deadline exceeded.",
            ));
        }
        // The provider follows redirects itself so every hop is scope-checked.
        // HTTP statuses remain normal responses; only transport/protocol failures
        // become errors. TLS validation stays at ureq's secure default.
        let response = self.request(url, budget.min(Duration::from_secs(20)))?;
        let status = response.status().as_u16();
        let headers = Self::headers(&response);
        let mut body = Vec::new();
        let _ = response
            .into_body()
            .into_reader()
            .take(self.body_cap as u64)
            .read_to_end(&mut body);
        Ok(WebResponse {
            status,
            headers,
            body,
        })
    }

    fn fetch_bounded(
        &self,
        url: &str,
        deadline: Instant,
        cancelled: &AtomicBool,
        cap: usize,
    ) -> Result<(WebResponse, bool)> {
        use std::io::Read;
        if cancelled.load(Ordering::SeqCst) {
            return Err(CoreError::new("Cancelled", "Request cancelled."));
        }
        let budget = deadline.saturating_duration_since(Instant::now());
        if budget.is_zero() {
            return Err(CoreError::new(
                "ProviderTimeout",
                "Request deadline exceeded.",
            ));
        }
        let response = self.request(url, budget)?;
        let status = response.status().as_u16();
        let headers = Self::headers(&response);
        let mut body = Vec::new();
        response
            .into_body()
            .into_reader()
            .take(cap as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|error| {
                CoreError::new("ProviderFailure", &format!("HTTP body read error: {error}"))
            })?;
        let truncated = body.len() > cap;
        body.truncate(cap);
        Ok((
            WebResponse {
                status,
                headers,
                body,
            },
            truncated,
        ))
    }

    fn built_in(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_transport_serves_and_defaults_404() {
        let t = StaticWebTransport::new().with_response(
            "https://example.test/",
            200,
            &[
                ("Server", "nginx"),
                ("Set-Cookie", "a=1"),
                ("Set-Cookie", "b=2"),
            ],
            "hi",
        );
        let cancelled = AtomicBool::new(false);
        let r = t
            .fetch(
                "https://example.test/",
                Instant::now() + Duration::from_secs(5),
                &cancelled,
            )
            .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.header("server"), Some("nginx"));
        assert_eq!(r.header_all("set-cookie"), vec!["a=1", "b=2"]);
        let miss = t
            .fetch(
                "https://example.test/missing",
                Instant::now() + Duration::from_secs(5),
                &cancelled,
            )
            .unwrap();
        assert_eq!(miss.status, 404);
    }

    #[test]
    fn bounded_fetch_reports_truncation() {
        let t = StaticWebTransport::new().with_response(
            "https://example.test/",
            200,
            &[],
            "0123456789",
        );
        let cancelled = AtomicBool::new(false);
        let deadline = Instant::now() + Duration::from_secs(5);
        let (r, cut) = t
            .fetch_bounded("https://example.test/", deadline, &cancelled, 4)
            .unwrap();
        assert!(cut);
        assert_eq!(r.body, b"0123");
        let (r, cut) = t
            .fetch_bounded("https://example.test/", deadline, &cancelled, 10)
            .unwrap();
        assert!(!cut);
        assert_eq!(r.body.len(), 10);
    }

    #[test]
    fn static_transport_honors_cancellation() {
        let t = StaticWebTransport::new();
        let cancelled = AtomicBool::new(true);
        assert_eq!(
            t.fetch("https://example.test/", Instant::now(), &cancelled)
                .unwrap_err()
                .code,
            "Cancelled"
        );
    }
}
