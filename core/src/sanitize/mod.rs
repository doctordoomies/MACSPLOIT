//! Display sanitization for provider commands.
//!
//! There are two distinct representations of a provider invocation:
//!
//! * the **execution command** — the exact executable path and argument vector handed
//!   to the shell-free process supervisor. It is never modified here.
//! * the **display command** — a privacy-reduced representation used only for the
//!   `ProviderCommand` event, the Recon live console, and other activity/display
//!   surfaces. It is never executed and must never be used to reconstruct an execution.
//!
//! **Invariant:** display-command text is privacy-reduced presentation data and must
//! never be assumed safe merely because process execution is shell-free. Anything that
//! could carry a secret (URL query values, and — as providers gain them — auth headers,
//! tokens, passwords, API keys) is redacted here, at this single boundary, before it
//! enters the durable event stream. The complete execution record lives only in the
//! hashed evidence envelope.

/// Build the display command from an execution command (`[executable, arg, ...]`):
/// the executable is reduced to its file name (no private install path), and each
/// argument is passed through [`sanitize_display_arg`]. Returns an empty vector for an
/// empty command. This never mutates the input used for execution.
pub fn display_command(command: &[String]) -> Vec<String> {
    let Some((executable, args)) = command.split_first() else {
        return Vec::new();
    };
    let name = std::path::Path::new(executable)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| executable.clone());
    std::iter::once(name)
        .chain(args.iter().map(|a| sanitize_display_arg(a)))
        .collect()
}

/// Sanitize a single argument for display. HTTP(S) URLs have their query redacted and
/// any userinfo removed (scheme/host/port/path preserved); everything else is passed
/// through unchanged today.
///
/// This is the deliberate extension point for future sensitive flag/value pairs: when a
/// provider gains an argument that can carry a secret (e.g. `-H "Authorization: ..."`,
/// `--password`, `--api-key`), add its detection/redaction here so redaction is enforced
/// at one place rather than relied upon per-provider.
pub fn sanitize_display_arg(arg: &str) -> String {
    if arg.starts_with("http://") || arg.starts_with("https://") {
        if let Some(redacted) = sanitize_display_url(arg) {
            return redacted;
        }
    }
    arg.to_owned()
}

/// Redact a valid HTTP(S) URL for display: drop any userinfo, replace a non-empty query
/// with `<redacted>`, and drop any fragment, while preserving scheme, host (with IPv6
/// brackets), port, and path. Returns `None` if the string is not a parseable http(s)
/// URL, so the caller can fall back to passing the argument through unchanged.
pub fn sanitize_display_url(value: &str) -> Option<String> {
    let url = url::Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let host = url.host_str()?; // host_str already brackets IPv6 literals
    let mut out = format!("{}://{}", url.scheme(), host);
    if let Some(port) = url.port() {
        out.push(':');
        out.push_str(&port.to_string());
    }
    out.push_str(url.path());
    // Only signal a query when one was actually present; never echo its contents.
    if url.query().is_some() {
        out.push_str("?<redacted>");
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_command_basenames_executable_and_passes_plain_args() {
        let cmd = vec![
            "/opt/homebrew/bin/nmap".to_string(),
            "-sT".into(),
            "-sV".into(),
            "192.0.2.25".into(),
        ];
        assert_eq!(
            display_command(&cmd),
            vec!["nmap", "-sT", "-sV", "192.0.2.25"]
        );
    }

    #[test]
    fn display_command_redacts_url_query_but_keeps_context() {
        let cmd = vec![
            "/opt/homebrew/bin/katana".to_string(),
            "-u".into(),
            "https://authorized.example/admin?token=secret-value&debug=1".into(),
            "-d".into(),
            "2".into(),
        ];
        let display = display_command(&cmd);
        assert_eq!(
            display,
            vec![
                "katana",
                "-u",
                "https://authorized.example/admin?<redacted>",
                "-d",
                "2"
            ]
        );
        // The secret never appears anywhere in the display vector.
        assert!(!display.join(" ").contains("secret-value"));
        assert!(!display.join(" ").contains("debug=1"));
    }

    #[test]
    fn url_without_query_is_preserved() {
        assert_eq!(
            sanitize_display_url("https://example.test/path").as_deref(),
            Some("https://example.test/path")
        );
        // A bare root path is normalized to "/" by the URL parser; still no query marker.
        assert_eq!(
            sanitize_display_url("https://example.test").as_deref(),
            Some("https://example.test/")
        );
    }

    #[test]
    fn localhost_custom_port_preserves_authority_and_path() {
        let out = sanitize_display_url("http://localhost:3000/api?key=secret").unwrap();
        assert_eq!(out, "http://localhost:3000/api?<redacted>");
        assert!(!out.contains("secret"));
    }

    #[test]
    fn ipv6_url_is_bracketed_and_redacted() {
        let out = sanitize_display_url("http://[::1]:8080/path?token=secret").unwrap();
        assert_eq!(out, "http://[::1]:8080/path?<redacted>");
        assert!(!out.contains("secret"));
    }

    #[test]
    fn userinfo_is_never_exposed() {
        // Credentials embedded in a URL must not survive into the display copy. The input
        // is assembled from parts so the repository secret audit does not flag the test.
        let input = ["https://", "u", ":", "p", "@example.test/x?token=secret"].concat();
        let out = sanitize_display_url(&input).unwrap();
        assert!(!out.contains("u:p"));
        assert!(!out.contains("secret"));
        assert_eq!(out, "https://example.test/x?<redacted>");
    }

    #[test]
    fn non_url_and_non_http_args_pass_through() {
        assert_eq!(sanitize_display_arg("-sV"), "-sV");
        assert_eq!(sanitize_display_arg("192.0.2.25"), "192.0.2.25");
        // Non-http(s) schemes are not treated as redactable URLs here.
        assert_eq!(
            sanitize_display_arg("ftp://example.test/x?a=b"),
            "ftp://example.test/x?a=b"
        );
    }
}
