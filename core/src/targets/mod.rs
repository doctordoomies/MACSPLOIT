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

pub fn classify(input: &str) -> Result<(TargetType, String)> {
    let value = input.trim();
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
}
