use crate::{
    assets::Id,
    error::{CoreError, Result},
};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, str::FromStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetType {
    Domain,
    URL,
    IPAddress,
    CIDR,
    Hostname,
    Username,
    EmailAddress,
    PhoneNumber,
    Repository,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub id: Id,
    pub workspace_id: Id,
    pub original_value: String,
    pub normalized_value: String,
    pub target_type: TargetType,
    pub created_at: String,
    pub asset_id: Option<Id>,
}

pub fn domain(value: &str) -> Result<String> {
    let input = value.strip_suffix('.').unwrap_or(value);
    let host = url::Host::parse(input).map_err(|_| invalid())?;
    let url::Host::Domain(normalized) = host else {
        return Err(invalid());
    };
    if normalized.is_empty()
        || normalized.len() > 253
        || normalized.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
    {
        return Err(invalid());
    }
    Ok(normalized.to_lowercase())
}

pub fn web_url(value: &str) -> Result<String> {
    let mut parsed = url::Url::parse(value).map_err(|_| invalid())?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(invalid());
    }
    parsed.set_fragment(None);
    Ok(parsed.into())
}

fn invalid() -> CoreError {
    CoreError::new(
        "InvalidTarget",
        "Enter a valid domain, HTTP(S) URL, IP, CIDR, email, hostname, or @username.",
    )
}

/// Characters allowed in a phone number as typed (digits plus common separators).
fn phone_shaped(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, ' ' | '-' | '.' | '(' | ')'))
}

/// Normalize an international phone number to E.164 (`+` followed by 7–15 digits,
/// country code not starting with 0). Only explicit international input is
/// accepted: a number without a leading `+` (or `tel:+`) is ambiguous and is
/// rejected rather than guessing a country. Returns `None` when `value` is not
/// phone-shaped at all, so other target classes can be tried.
pub fn phone(value: &str) -> Option<Result<String>> {
    let rest = value
        .strip_prefix("tel:")
        .or_else(|| value.strip_prefix("TEL:"))
        .unwrap_or(value);
    let ambiguous = || {
        CoreError::new(
            "InvalidTarget",
            "Enter a phone number in international format starting with + and the country code (e.g. +1 202 555 0143). MACSPLOIT does not guess the country.",
        )
    };
    match rest.strip_prefix('+') {
        Some(body) => {
            if !phone_shaped(body) {
                return None;
            }
            let digits: String = body.chars().filter(char::is_ascii_digit).collect();
            if !(7..=15).contains(&digits.len()) || digits.starts_with('0') {
                return Some(Err(ambiguous()));
            }
            Some(Ok(format!("+{digits}")))
        }
        None => {
            // National-format input such as "(202) 555-0143" or "202-555-0143":
            // phone-shaped with separators and at least 7 digits, but no country.
            let digits = rest.chars().filter(char::is_ascii_digit).count();
            let has_separator = rest.chars().any(|c| matches!(c, ' ' | '-' | '(' | ')'));
            (phone_shaped(rest) && has_separator && digits >= 7 && !rest.contains('.'))
                .then(|| Err(ambiguous()))
        }
    }
}

pub fn classify(input: &str) -> Result<(TargetType, String)> {
    let value = input.trim();
    // Phone numbers are the only class that may contain inner spaces.
    if !value.is_empty() && value.len() <= 64 && !value.chars().any(char::is_control) {
        if let Some(result) = phone(value) {
            return result.map(|e164| (TargetType::PhoneNumber, e164));
        }
    }
    if value.is_empty()
        || value.len() > 2048
        || value.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(invalid());
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok((TargetType::IPAddress, ip.to_string()));
    }
    if let Ok(network) = value.parse::<ipnet::IpNet>() {
        return Ok((TargetType::CIDR, network.trunc().to_string()));
    }
    if value.contains("://") {
        return Ok((TargetType::URL, web_url(value)?));
    }
    if let Some(username) = value.strip_prefix('@') {
        if username.is_empty()
            || username.len() > 64
            || !username
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        {
            return Err(invalid());
        }
        return Ok((TargetType::Username, format!("@{username}")));
    }
    if value.contains('@') {
        email_address::EmailAddress::from_str(value).map_err(|_| invalid())?;
        let (local, host) = value.rsplit_once('@').ok_or_else(invalid)?;
        return Ok((
            TargetType::EmailAddress,
            format!("{local}@{}", domain(host)?),
        ));
    }
    // Reject malformed numeric IPs instead of misclassifying them as domains.
    if value.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(invalid());
    }
    let normalized = domain(value)?;
    Ok((
        if normalized.contains('.') {
            TargetType::Domain
        } else {
            TargetType::Hostname
        },
        normalized,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn required_target_classes() {
        for (input, kind, normalized) in [
            ("EXAMPLE.COM.", TargetType::Domain, "example.com"),
            (
                "https://example.com/path#fragment",
                TargetType::URL,
                "https://example.com/path",
            ),
            ("192.0.2.10", TargetType::IPAddress, "192.0.2.10"),
            ("192.0.2.1/24", TargetType::CIDR, "192.0.2.0/24"),
            (
                "person@EXAMPLE.COM",
                TargetType::EmailAddress,
                "person@example.com",
            ),
            ("@username", TargetType::Username, "@username"),
            ("localhost", TargetType::Hostname, "localhost"),
            ("2001:db8::1", TargetType::IPAddress, "2001:db8::1"),
            ("2001:db8::1/32", TargetType::CIDR, "2001:db8::/32"),
        ] {
            assert_eq!(classify(input).unwrap(), (kind, normalized.into()));
        }
    }
    #[test]
    fn phone_numbers_require_international_format() {
        for (input, normalized) in [
            ("+12025550143", "+12025550143"),
            ("+1 202 555 0143", "+12025550143"),
            ("+1 (202) 555-0143", "+12025550143"),
            ("tel:+33.1.99.00.12.34", "+33199001234"),
        ] {
            assert_eq!(
                classify(input).unwrap(),
                (TargetType::PhoneNumber, normalized.into()),
                "{input}"
            );
        }
        // Ambiguous national formats and impossible lengths are rejected, never guessed.
        for input in [
            "(202) 555-0143",
            "202-555-0143",
            "+0123456789",
            "+12",
            "+1234567890123456",
        ] {
            let err = classify(input).unwrap_err();
            assert!(err.message.contains("international format"), "{input}");
        }
        // Not phone-shaped: other classes are unaffected.
        assert_eq!(classify("192.0.2.1").unwrap().0, TargetType::IPAddress);
        assert!(classify("+1;rm").is_err());
        assert!(classify("+1 202 555 0143 ext").is_err());
    }

    #[test]
    fn unicode_domain_uses_idna() {
        assert_eq!(
            classify("bücher.example").unwrap().1,
            "xn--bcher-kva.example"
        );
    }
    #[test]
    fn rejects_invalid_or_shell_shaped_targets() {
        for input in [
            "",
            "-option",
            "a..test",
            "example.test..",
            "x;whoami",
            "$(id)",
            "@",
            "999.1.1.1",
            "192.0.2.1/99",
            "file:///tmp/x",
            "a@",
            "a b.test",
        ] {
            assert!(classify(input).is_err(), "accepted {input}");
        }
        let credential_url = ["https://", "user:pass", "@example.test"].concat();
        assert!(classify(&credential_url).is_err());
    }
    #[test]
    fn url_retains_query_and_normalizes_default_port() {
        assert_eq!(
            web_url("HTTPS://EXAMPLE.TEST:443/a?x=1#b").unwrap(),
            "https://example.test/a?x=1"
        );
    }

    #[test]
    fn classifies_local_and_private_targets() {
        // Bare scope-style entries: localhost is a single-label Hostname; loopback and
        // private literals (v4/v6) are IPAddresses; dotted dev names are Domains.
        for (input, kind, normalized) in [
            ("localhost", TargetType::Hostname, "localhost"),
            ("LOCALHOST", TargetType::Hostname, "localhost"),
            ("127.0.0.1", TargetType::IPAddress, "127.0.0.1"),
            ("::1", TargetType::IPAddress, "::1"),
            ("192.168.1.50", TargetType::IPAddress, "192.168.1.50"),
            ("10.0.0.5", TargetType::IPAddress, "10.0.0.5"),
            ("app.localhost", TargetType::Domain, "app.localhost"),
            (
                "target-company.test",
                TargetType::Domain,
                "target-company.test",
            ),
            ("127.0.0.0/8", TargetType::CIDR, "127.0.0.0/8"),
            ("192.168.1.0/24", TargetType::CIDR, "192.168.1.0/24"),
            ("10.0.0.0/8", TargetType::CIDR, "10.0.0.0/8"),
        ] {
            assert_eq!(
                classify(input).unwrap(),
                (kind, normalized.into()),
                "{input}"
            );
        }
    }

    #[test]
    fn local_web_urls_normalize_host_port_and_ipv6_brackets() {
        // Custom ports are preserved, host case is lowered, IPv6 literals keep their
        // brackets, and a default port is dropped — all without public DNS.
        for (input, normalized) in [
            ("http://localhost:3000", "http://localhost:3000/"),
            ("http://LOCALHOST:3000", "http://localhost:3000/"),
            ("http://127.0.0.1:8080", "http://127.0.0.1:8080/"),
            ("http://[::1]:8080", "http://[::1]:8080/"),
            ("http://[::1]:8080/", "http://[::1]:8080/"),
            ("http://app.localhost:5173", "http://app.localhost:5173/"),
            (
                "http://target-company.test:3000/x?q=1",
                "http://target-company.test:3000/x?q=1",
            ),
            ("http://localhost:80", "http://localhost/"),
            ("http://192.168.1.50:8000", "http://192.168.1.50:8000/"),
        ] {
            assert_eq!(
                classify(input).unwrap(),
                (TargetType::URL, normalized.into())
            );
            assert_eq!(web_url(input).unwrap(), normalized, "{input}");
        }
    }

    #[test]
    fn credential_bearing_local_urls_are_rejected() {
        // Loopback status is not a shortcut around the credential-URL rule.
        let credential_url = ["http://", "user:pass", "@localhost:3000/"].concat();
        assert!(classify(&credential_url).is_err());
        assert!(web_url(&credential_url).is_err());
    }
}
