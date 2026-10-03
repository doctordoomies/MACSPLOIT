use crate::{
    error::{CoreError, Result},
    providers::RiskClass,
    targets::{classify, TargetType},
};

pub fn normalize_entry(input: &str) -> Result<String> {
    if let Some(suffix) = input.strip_prefix("*.") {
        let domain = crate::targets::domain(suffix)?;
        if !domain.contains('.') {
            return Err(CoreError::new(
                "ScopeViolation",
                "A wildcard needs a domain suffix.",
            ));
        }
        return Ok(format!("*.{domain}"));
    }
    let (kind, value) = classify(input)?;
    if matches!(
        kind,
        TargetType::Domain | TargetType::Hostname | TargetType::IPAddress | TargetType::CIDR
    ) {
        Ok(value)
    } else {
        Err(CoreError::new(
            "ScopeViolation",
            "Scope accepts domains, wildcards, IPs, and CIDRs.",
        ))
    }
}

pub fn contains(entries: &[String], target: &str) -> bool {
    let Ok((kind, value)) = classify(target) else {
        return false;
    };
    let host = if kind == TargetType::URL {
        let Ok(url) = url::Url::parse(&value) else {
            return false;
        };
        url.host_str()
            .unwrap_or("")
            .trim_matches(['[', ']'])
            .to_owned()
    } else {
        value
    };
    entries.iter().any(|entry| {
        if let Some(suffix) = entry.strip_prefix("*.") {
            host.ends_with(&format!(".{suffix}")) && host != suffix
        } else if let Ok(network) = entry.parse::<ipnet::IpNet>() {
            host.parse::<std::net::IpAddr>()
                .is_ok_and(|ip| network.contains(&ip))
        } else {
            *entry == host
        }
    })
}

pub fn authorize(
    entries: &[String],
    target: &str,
    risk: RiskClass,
    active_approved: bool,
) -> Result<()> {
    if matches!(risk, RiskClass::Validation | RiskClass::LabOnly) {
        return Err(CoreError::new(
            "ScopeViolation",
            "Validation and lab providers are disabled in Phase 0.",
        ));
    }
    if !contains(entries, target) {
        return Err(CoreError::new(
            "ScopeViolation",
            "The target is outside the workspace scope.",
        ));
    }
    // Passive and low-impact work (e.g. DNS resolution) runs on any in-scope
    // target. Only full Active work requires explicit analyst approval.
    if risk == RiskClass::Active && !active_approved {
        return Err(CoreError::new(
            "ScopeViolation",
            "Active work requires explicit approval.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entries() -> Vec<String> {
        vec![
            "example.test".into(),
            "*.example.test".into(),
            "192.0.2.0/24".into(),
        ]
    }
    #[test]
    fn scope_matches_boundaries_not_substrings() {
        for input in [
            "example.test",
            "api.example.test",
            "192.0.2.10",
            "https://api.example.test/a",
        ] {
            assert!(contains(&entries(), input));
        }
        for input in [
            "badexample.test",
            "example.test.attacker.test",
            "198.51.100.1",
        ] {
            assert!(!contains(&entries(), input));
        }
    }
    #[test]
    fn active_out_of_scope_and_unapproved_work_is_denied() {
        assert!(authorize(&entries(), "outside.test", RiskClass::Active, true).is_err());
        assert!(authorize(&entries(), "example.test", RiskClass::Active, false).is_err());
        assert!(authorize(&entries(), "example.test", RiskClass::Passive, false).is_ok());
        assert!(authorize(&entries(), "example.test", RiskClass::LabOnly, true).is_err());
        // Low-impact work (DNS) is allowed on an in-scope target without approval,
        // but still denied out of scope.
        assert!(authorize(
            &entries(),
            "example.test",
            RiskClass::ActiveLowImpact,
            false
        )
        .is_ok());
        assert!(authorize(
            &entries(),
            "outside.test",
            RiskClass::ActiveLowImpact,
            false
        )
        .is_err());
    }
    #[test]
    fn scope_entries_are_validated_and_ipv6_supported() {
        assert_eq!(normalize_entry("*.EXAMPLE.TEST").unwrap(), "*.example.test");
        assert!(normalize_entry("https://example.test").is_err());
        assert!(contains(&["2001:db8::/32".into()], "2001:db8::1"));
    }

    #[test]
    fn local_and_private_scope_entries_normalize() {
        // Local/private hosts, literals, and CIDRs are valid scope entries; a URL is not.
        for entry in [
            "localhost",
            "app.localhost",
            "target-company.test",
            "127.0.0.1",
            "127.0.0.0/8",
            "::1",
            "192.168.1.50",
            "192.168.1.0/24",
            "10.0.0.0/8",
        ] {
            assert!(normalize_entry(entry).is_ok(), "entry {entry}");
        }
        // A single-label wildcard suffix (e.g. *.localhost) has no dotted domain and is
        // rejected: local wildcards must be authorized as explicit hosts instead.
        assert!(normalize_entry("*.localhost").is_err());
    }

    #[test]
    fn local_url_targets_match_explicit_local_scope() {
        // localhost host + custom port.
        assert!(contains(&["localhost".into()], "http://localhost:3000"));
        // Loopback CIDR covers the IPv4 loopback literal with any port.
        assert!(contains(&["127.0.0.0/8".into()], "http://127.0.0.1:8080"));
        assert!(contains(&["127.0.0.0/8".into()], "http://127.0.0.1:9999/x"));
        // IPv6 loopback literal (brackets stripped from the URL host) matches exactly.
        assert!(contains(&["::1".into()], "http://[::1]:8080"));
        assert!(contains(&["::1/128".into()], "http://[::1]:3000/"));
        // Private CIDR boundaries.
        assert!(contains(
            &["192.168.1.0/24".into()],
            "http://192.168.1.50:8000"
        ));
        assert!(!contains(
            &["192.168.1.0/24".into()],
            "http://192.168.2.50:8000"
        ));
        assert!(contains(&["10.0.0.0/8".into()], "http://10.0.0.5:5000"));
        // Exact dev hostnames (via /etc/hosts at runtime); dotted names are Domains.
        assert!(contains(
            &["target-company.test".into()],
            "http://target-company.test:3000"
        ));
    }

    #[test]
    fn local_scope_does_not_widen_or_conflate_distinct_hosts() {
        // localhost, 127.0.0.1 and ::1 are distinct authorization identities.
        assert!(!contains(&["localhost".into()], "http://127.0.0.1:3000"));
        assert!(!contains(&["127.0.0.1".into()], "http://localhost:3000"));
        assert!(!contains(&["localhost".into()], "http://[::1]:3000"));
        // An exact localhost entry never implicitly authorizes a subdomain label.
        assert!(!contains(
            &["localhost".into()],
            "http://app.localhost:5173"
        ));
        // A single loopback literal is not the whole range.
        assert!(!contains(&["127.0.0.1".into()], "http://127.0.0.2:8080"));
    }

    #[test]
    fn local_targets_follow_the_same_authorization_rules() {
        // Local/private status is not authorization: the target must be in scope, and
        // Active work still needs explicit approval — exactly as for public targets.
        let scope = vec!["localhost".to_string(), "127.0.0.0/8".to_string()];
        assert!(authorize(
            &scope,
            "http://localhost:3000",
            RiskClass::ActiveLowImpact,
            false
        )
        .is_ok());
        assert!(authorize(&scope, "http://127.0.0.1:8080", RiskClass::Active, true).is_ok());
        assert!(authorize(&scope, "http://127.0.0.1:8080", RiskClass::Active, false).is_err());
        // Out of scope local host is denied even though it is loopback-adjacent.
        assert_eq!(
            authorize(
                &scope,
                "http://192.168.1.5:8080",
                RiskClass::ActiveLowImpact,
                false
            )
            .unwrap_err()
            .code,
            "ScopeViolation"
        );
    }
}
