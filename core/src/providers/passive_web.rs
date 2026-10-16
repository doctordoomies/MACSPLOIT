//! Shared plumbing for the built-in passive Domain-OSINT HTTP clients (native RDAP
//! and certificate transparency). Each client performs a small, fixed number of
//! bounded HTTPS GETs to well-known public services — never to the subject domain
//! or any discovered host — and reports every request in a compact JSON request log
//! (the execution's stdout). Raw response bodies become separate hashed evidence
//! records (chunked to the 1 MiB evidence bound) before anything is parsed, and a
//! transport failure, timeout, or cancellation still yields an [`Execution`] so the
//! request log is preserved as evidence.

use super::{Capability, Execution, ExecutionArtifact};
use crate::{
    error::{CoreError, Result},
    web::WebResponse,
};
use serde_json::{json, Value};

/// Raw response bytes per evidence record (the evidence store's 1 MiB bound).
pub const EVIDENCE_CHUNK: usize = 1024 * 1024;

/// Validate a Domain-OSINT run and return the canonical domain.
pub fn domain_subject(target: &str, capability: Capability, provider: &str) -> Result<String> {
    if capability != Capability::DomainOsint {
        return Err(CoreError::new(
            "ProviderUnsupported",
            &format!("{provider} only provides domain OSINT."),
        ));
    }
    crate::targets::domain(target)
        .map_err(|_| CoreError::new("InvalidTarget", "Domain OSINT requires a domain target."))
}

/// A plain `https` URL without credentials (the only scheme these clients use).
pub fn https_url(value: &str) -> Option<url::Url> {
    let parsed = url::Url::parse(value).ok()?;
    (parsed.scheme() == "https"
        && parsed.host_str().is_some()
        && parsed.username().is_empty()
        && parsed.password().is_none())
    .then_some(parsed)
}

/// The compact per-run request log written to stdout (and so to the evidence
/// envelope). It never contains response bodies.
pub struct RequestLog {
    provider: &'static str,
    domain: String,
    started_at: String,
    requests: Vec<Value>,
    notes: Vec<String>,
}

impl RequestLog {
    pub fn new(provider: &'static str, domain: &str) -> Self {
        Self {
            provider,
            domain: domain.to_owned(),
            started_at: crate::now(),
            requests: Vec::new(),
            notes: Vec::new(),
        }
    }

    pub fn response(&mut self, purpose: &str, url: &str, response: &WebResponse, truncated: bool) {
        self.requests.push(json!({
            "purpose": purpose,
            "url": url,
            "status": response.status,
            "bytes": response.body.len(),
            "truncated": truncated,
            "content_type": response
                .header("content-type")
                .map(|v| crate::osint::clean_text(v, 128)),
        }));
    }

    pub fn failure(&mut self, purpose: &str, url: &str, error: &CoreError) {
        self.requests.push(json!({
            "purpose": purpose,
            "url": url,
            "error_code": error.code,
            "error": crate::osint::clean_text(&error.message, 256),
        }));
    }

    pub fn note(&mut self, note: impl Into<String>) {
        if self.notes.len() < 16 {
            self.notes.push(note.into());
        }
    }

    fn report(&self, outcome: &str, extra: Value) -> Value {
        let mut report = json!({
            "provider": self.provider,
            "domain": self.domain,
            "outcome": outcome,
            "requests": self.requests,
            "notes": self.notes,
        });
        if let (Some(object), Value::Object(extra)) = (report.as_object_mut(), extra) {
            for (key, value) in extra {
                object.entry(key).or_insert(value);
            }
        }
        report
    }
}

/// How a run ended, which decides the execution's exit/timeout/cancel flags.
pub enum RunEnd {
    /// Requests completed; the parser decides what the outcome means.
    Completed(&'static str),
    /// A request failed (transport, HTTP status, refused redirect): exit 1.
    Failed(&'static str),
    /// Mapped from the transport error code.
    Error(CoreError),
}

/// Assemble the execution. Always succeeds so the request log is persisted as
/// evidence even for a timeout, transport failure, or cancellation.
pub fn execution(
    target: &str,
    capability: Capability,
    log: &RequestLog,
    end: RunEnd,
    extra: Value,
    artifacts: Vec<ExecutionArtifact>,
) -> Result<Execution> {
    let (outcome, exit_status, timed_out, cancelled) = match &end {
        RunEnd::Completed(outcome) => (*outcome, Some(0), false, false),
        RunEnd::Failed(outcome) => (*outcome, Some(1), false, false),
        RunEnd::Error(error) if error.code == "Cancelled" => ("cancelled", None, false, true),
        RunEnd::Error(error) if error.code == "ProviderTimeout" => ("timeout", None, true, false),
        RunEnd::Error(_) => ("transport_error", Some(1), false, false),
    };
    Ok(Execution {
        target: target.into(),
        capability,
        // A display command for the console; there is no process or argv.
        command: vec![log.provider.to_owned(), log.domain.clone()],
        stdout: serde_json::to_vec_pretty(&log.report(outcome, extra))?,
        stderr: Vec::new(),
        exit_status,
        pid: None,
        timed_out,
        started_at: log.started_at.clone(),
        ended_at: crate::now(),
        artifacts,
        cancelled,
    })
}

/// Split a raw response body into evidence-sized artifacts `<name>`, `<name>_2`, ….
pub fn chunk_artifacts(name: &str, body: &[u8]) -> Vec<ExecutionArtifact> {
    body.chunks(EVIDENCE_CHUNK)
        .enumerate()
        .map(|(index, chunk)| ExecutionArtifact {
            name: if index == 0 {
                name.to_owned()
            } else {
                format!("{name}_{}", index + 1)
            },
            bytes: chunk.to_vec(),
            observed_bytes: Some(chunk.len() as u64),
            over_limit: false,
        })
        .collect()
}

/// Reassemble a chunked body captured by [`chunk_artifacts`].
pub fn body_from_artifacts(execution: &Execution, name: &str) -> Option<Vec<u8>> {
    let first = execution.artifacts.iter().find(|a| a.name == name)?;
    let mut body = first.bytes.clone();
    for index in 2.. {
        let part = format!("{name}_{index}");
        match execution.artifacts.iter().find(|a| a.name == part) {
            Some(artifact) => body.extend_from_slice(&artifact.bytes),
            None => break,
        }
    }
    Some(body)
}

/// Parse the request log back from stdout.
pub fn report(execution: &Execution, provider: &str) -> Result<Value> {
    let report: Value = serde_json::from_slice(&execution.stdout).map_err(|_| {
        CoreError::new(
            "ProviderFailure",
            &format!("{provider} request log is malformed."),
        )
    })?;
    if !report.is_object() {
        return Err(CoreError::new(
            "ProviderFailure",
            &format!("{provider} request log is malformed."),
        ));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_https_urls_are_accepted() {
        assert!(https_url("https://rdap.example.test/v1/").is_some());
        for bad in [
            "http://rdap.example.test/",
            "https://user@rdap.example.test/",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "not a url",
        ] {
            assert!(https_url(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn bodies_chunk_and_reassemble_at_the_evidence_bound() {
        let body = vec![b'x'; EVIDENCE_CHUNK * 2 + 10];
        let parts = chunk_artifacts("ct_response", &body);
        assert_eq!(parts.len(), 3);
        assert!(parts.iter().all(|p| p.bytes.len() <= EVIDENCE_CHUNK));
        let execution = Execution {
            target: "example.test".into(),
            capability: Capability::DomainOsint,
            command: vec![],
            stdout: vec![],
            stderr: vec![],
            exit_status: Some(0),
            pid: None,
            timed_out: false,
            started_at: String::new(),
            ended_at: String::new(),
            artifacts: parts,
            cancelled: false,
        };
        assert_eq!(
            body_from_artifacts(&execution, "ct_response").unwrap(),
            body
        );
        assert!(body_from_artifacts(&execution, "missing").is_none());
    }
}
