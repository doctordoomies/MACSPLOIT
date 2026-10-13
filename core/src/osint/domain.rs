//! Domain / public-infrastructure OSINT normalization (Issue #66), shared by the
//! theHarvester, native RDAP, and native certificate-transparency providers.
//!
//! Every value here comes from an untrusted public source. Names are re-validated
//! with the core's domain normalizer, kept only when they fall inside the subject
//! domain (or, for nameservers, are syntactically valid hosts), deduplicated, and
//! bounded. Each accepted value becomes a canonical asset (the same `Subdomain`
//! type Subfinder produces, so passive sources deduplicate against existing recon
//! data) plus one per-run observation that records the provider, the passive
//! nature of the claim, and that liveness is unverified. MACSPLOIT never resolves,
//! probes, or otherwise contacts a discovered host from this path.

use super::{clean_text, email_identity, CONFIDENCE_REPORTED, MAX_FIELD_BYTES, MAX_SUMMARY_LIST};
use crate::{
    assets::{AssetType, Discovery, ObservationDetail, RelationshipType},
    providers::ParsedOutput,
};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

/// Shown with every domain-OSINT observation.
pub const PASSIVE_NOTE: &str = "Passive public-source observation: not proof that the host exists, resolves, or is live today. MACSPLOIT did not contact it.";
/// Certificate-transparency names are historical by nature.
pub const CT_NOTE: &str = "Certificate-transparency name: a publicly logged certificate once named this host. Historical; not proof that it exists, resolves, or is live today. MACSPLOIT did not contact it.";
/// `subject_kind` of a Domain OSINT run summary.
pub const DOMAIN_SUBJECT_KIND: &str = "DOMAIN";
/// Hosts (subdomains) accepted per run; the rest are counted as dropped.
pub const MAX_HOSTS: usize = 250;
/// Email addresses accepted per run.
pub const MAX_EMAILS: usize = 100;
/// IP addresses accepted per run.
pub const MAX_IPS: usize = 100;
/// Nameservers accepted per run.
pub const MAX_NAMESERVERS: usize = 20;
/// Per-observation fact keys kept.
const MAX_FACTS: usize = 16;

/// How one reported name relates to the subject domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameClass {
    /// The subject domain itself.
    Subject,
    /// A strict subdomain (canonical, lowercase, no trailing dot).
    Subdomain(String),
    /// A valid name outside the subject domain (not kept as a subdomain).
    OutOfDomain(String),
    /// Not a valid DNS name.
    Invalid,
}

/// Classify a reported name against the canonical subject domain. Strips one
/// trailing dot; never accepts wildcards (callers strip and flag `*.` first).
pub fn classify_name(domain: &str, raw: &str) -> NameClass {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > 253 || raw.contains('*') {
        return NameClass::Invalid;
    }
    let Ok(name) = crate::targets::domain(raw) else {
        return NameClass::Invalid;
    };
    if name == domain {
        NameClass::Subject
    } else if name.ends_with(&format!(".{domain}")) {
        NameClass::Subdomain(name)
    } else {
        NameClass::OutOfDomain(name)
    }
}

/// Counters for values a provider reported that MACSPLOIT did not keep.
#[derive(Debug, Default, Clone)]
pub struct Dropped {
    pub out_of_domain: usize,
    pub invalid: usize,
    pub over_limit: usize,
}

/// Bounded, deduplicated findings for one provider run on one domain.
#[derive(Debug, Clone)]
pub struct DomainFindings {
    pub domain: String,
    hosts: BTreeMap<String, Map<String, Value>>,
    emails: BTreeMap<String, Map<String, Value>>,
    /// ip -> (host it was reported for, facts)
    ips: BTreeMap<String, (Option<String>, Map<String, Value>)>,
    nameservers: BTreeMap<String, Map<String, Value>>,
    pub dropped: Dropped,
}

fn merge_facts(into: &mut Map<String, Value>, facts: Map<String, Value>) {
    for (key, value) in facts {
        if into.len() >= MAX_FACTS && !into.contains_key(&key) {
            break;
        }
        into.entry(key).or_insert(value);
    }
}

impl DomainFindings {
    pub fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_owned(),
            hosts: BTreeMap::new(),
            emails: BTreeMap::new(),
            ips: BTreeMap::new(),
            nameservers: BTreeMap::new(),
            dropped: Dropped::default(),
        }
    }

    /// Record a reported host. Returns the canonical subdomain when kept (the
    /// subject itself is accepted silently but not stored as a subdomain).
    pub fn add_host(&mut self, raw: &str, facts: Map<String, Value>) -> Option<String> {
        match classify_name(&self.domain, raw) {
            NameClass::Subdomain(name) => {
                if let Some(existing) = self.hosts.get_mut(&name) {
                    merge_facts(existing, facts);
                    return Some(name);
                }
                if self.hosts.len() >= MAX_HOSTS {
                    self.dropped.over_limit += 1;
                    return None;
                }
                let mut kept = Map::new();
                merge_facts(&mut kept, facts);
                self.hosts.insert(name.clone(), kept);
                Some(name)
            }
            NameClass::Subject => None,
            NameClass::OutOfDomain(_) => {
                self.dropped.out_of_domain += 1;
                None
            }
            NameClass::Invalid => {
                self.dropped.invalid += 1;
                None
            }
        }
    }

    /// Record a reported email address; kept only when its domain is the subject
    /// domain or one of its subdomains (a public source matching on a substring is
    /// not enough).
    pub fn add_email(&mut self, raw: &str, facts: Map<String, Value>) {
        let Ok(email) = email_identity(raw.trim()) else {
            self.dropped.invalid += 1;
            return;
        };
        let host = email.rsplit_once('@').map(|(_, d)| d).unwrap_or_default();
        if !matches!(
            classify_name(&self.domain, host),
            NameClass::Subject | NameClass::Subdomain(_)
        ) {
            self.dropped.out_of_domain += 1;
            return;
        }
        if let Some(existing) = self.emails.get_mut(&email) {
            merge_facts(existing, facts);
        } else if self.emails.len() >= MAX_EMAILS {
            self.dropped.over_limit += 1;
        } else {
            let mut kept = Map::new();
            merge_facts(&mut kept, facts);
            self.emails.insert(email, kept);
        }
    }

    /// Record an IP a passive source associated with `host` (a kept subdomain) or
    /// with the domain itself.
    pub fn add_ip(&mut self, raw: &str, host: Option<&str>, facts: Map<String, Value>) {
        let Ok(ip) = raw.trim().parse::<std::net::IpAddr>() else {
            self.dropped.invalid += 1;
            return;
        };
        let ip = ip.to_string();
        let host = host
            .filter(|h| self.hosts.contains_key(*h))
            .map(str::to_owned);
        if let Some((existing_host, existing)) = self.ips.get_mut(&ip) {
            if existing_host.is_none() {
                *existing_host = host;
            }
            merge_facts(existing, facts);
        } else if self.ips.len() >= MAX_IPS {
            self.dropped.over_limit += 1;
        } else {
            let mut kept = Map::new();
            merge_facts(&mut kept, facts);
            self.ips.insert(ip, (host, kept));
        }
    }

    /// Record a nameserver host from a registry record (may be outside the domain).
    pub fn add_nameserver(&mut self, raw: &str, facts: Map<String, Value>) {
        let name = match classify_name(&self.domain, raw) {
            NameClass::Subdomain(name) | NameClass::OutOfDomain(name) => name,
            NameClass::Subject | NameClass::Invalid => {
                self.dropped.invalid += 1;
                return;
            }
        };
        if let Some(existing) = self.nameservers.get_mut(&name) {
            merge_facts(existing, facts);
        } else if self.nameservers.len() >= MAX_NAMESERVERS {
            self.dropped.over_limit += 1;
        } else {
            let mut kept = Map::new();
            merge_facts(&mut kept, facts);
            self.nameservers.insert(name, kept);
        }
    }

    pub fn host_count(&self) -> usize {
        self.hosts.len()
    }
    pub fn email_count(&self) -> usize {
        self.emails.len()
    }
    pub fn ip_count(&self) -> usize {
        self.ips.len()
    }
    pub fn nameserver_count(&self) -> usize {
        self.nameservers.len()
    }
}

/// Per-run framing shared by every observation of one provider run.
pub struct RunFraming<'a> {
    pub provider_id: &'a str,
    /// True when every claim is historical by construction (certificate transparency).
    pub historical: bool,
    pub note: &'a str,
    /// Provider-specific bounded facts for the subject's run-summary observation
    /// (e.g. RDAP registration status/events).
    pub subject_facts: Map<String, Value>,
    /// Extra bounded summary fields (source lists, counts the provider tracks).
    pub extra: Map<String, Value>,
    /// The provider itself reported an incomplete result (e.g. a source failed).
    pub provider_partial: bool,
}

fn observation(framing: &RunFraming, facts: Map<String, Value>) -> ObservationDetail {
    let mut metadata = Map::new();
    metadata.insert("kind".into(), json!("osint_domain_observation"));
    metadata.insert("provider".into(), json!(framing.provider_id));
    metadata.insert("passive".into(), json!(true));
    metadata.insert("historical".into(), json!(framing.historical));
    metadata.insert("liveness".into(), json!("unverified"));
    metadata.insert("note".into(), json!(framing.note));
    if !facts.is_empty() {
        metadata.insert("facts".into(), Value::Object(facts));
    }
    ObservationDetail {
        confidence: CONFIDENCE_REPORTED.into(),
        metadata: Value::Object(metadata),
    }
}

/// Build the provider-neutral output: the subject Domain (with the run summary as
/// its observation), then kept subdomains, IPs, emails, and nameservers with their
/// relationships. Out-of-domain/invalid/over-limit values are counted, never kept.
pub fn build_domain_output(findings: DomainFindings, framing: RunFraming) -> ParsedOutput {
    let domain = findings.domain.clone();
    let dropped = findings.dropped.clone();
    let partial = framing.provider_partial || dropped.over_limit > 0;
    let mut summary = Map::new();
    summary.insert("kind".into(), json!("osint_run_summary"));
    summary.insert("provider".into(), json!(framing.provider_id));
    summary.insert("subject".into(), json!(domain));
    // Same SCREAMING_SNAKE_CASE convention as `osint::SubjectKind` (USERNAME, EMAIL,
    // PHONE): clients dispatch result presentation on this typed value.
    summary.insert("subject_kind".into(), json!(DOMAIN_SUBJECT_KIND));
    summary.insert(
        "counts".into(),
        json!({
            "hosts": findings.host_count(),
            "emails": findings.email_count(),
            "ips": findings.ip_count(),
            "nameservers": findings.nameserver_count(),
            "dropped_out_of_domain": dropped.out_of_domain,
            "dropped_invalid": dropped.invalid,
            "dropped_over_limit": dropped.over_limit,
        }),
    );
    summary.insert("passive".into(), json!(true));
    summary.insert("historical".into(), json!(framing.historical));
    summary.insert("partial".into(), json!(partial));
    summary.insert("note".into(), json!(framing.note));
    if !framing.subject_facts.is_empty() {
        summary.insert(
            "registration".into(),
            Value::Object(framing.subject_facts.clone()),
        );
    }
    for (key, value) in framing.extra.clone() {
        summary.entry(key).or_insert(value);
    }
    let summary = Value::Object(summary);

    let asset_metadata = |kind: &str| json!({"tool": framing.provider_id, "osint": kind});
    let mut discoveries = vec![Discovery {
        asset_type: AssetType::Domain,
        value: domain.clone(),
        source: None,
        relationship: None,
        observation: Some(ObservationDetail {
            confidence: CONFIDENCE_REPORTED.into(),
            metadata: summary.clone(),
        }),
        metadata: json!({"source": "Analyst"}),
    }];
    for (name, facts) in findings.hosts {
        discoveries.push(Discovery {
            asset_type: AssetType::Subdomain,
            value: name,
            source: Some(domain.clone()),
            relationship: Some(RelationshipType::HasSubdomain),
            observation: Some(observation(&framing, facts)),
            metadata: asset_metadata("domain_host"),
        });
    }
    for (ip, (host, facts)) in findings.ips {
        discoveries.push(Discovery {
            asset_type: AssetType::IPAddress,
            value: ip,
            source: Some(host.unwrap_or_else(|| domain.clone())),
            relationship: Some(RelationshipType::ObservedIp),
            observation: Some(observation(&framing, facts)),
            metadata: asset_metadata("domain_ip"),
        });
    }
    for (email, facts) in findings.emails {
        discoveries.push(Discovery {
            asset_type: AssetType::EmailAddress,
            value: email,
            source: Some(domain.clone()),
            relationship: Some(RelationshipType::HasEmail),
            observation: Some(observation(&framing, facts)),
            metadata: asset_metadata("domain_email"),
        });
    }
    for (name, facts) in findings.nameservers {
        let in_domain = matches!(classify_name(&domain, &name), NameClass::Subdomain(_));
        discoveries.push(Discovery {
            asset_type: if in_domain {
                AssetType::Subdomain
            } else {
                AssetType::Hostname
            },
            value: name,
            source: Some(domain.clone()),
            relationship: Some(RelationshipType::HasNameserver),
            observation: Some(observation(&framing, facts)),
            metadata: asset_metadata("domain_nameserver"),
        });
    }
    ParsedOutput {
        discoveries,
        partial,
        summary: Some(summary),
    }
}

/// A bounded, cleaned string fact.
pub fn text_fact(value: &str) -> Value {
    Value::String(clean_text(value, MAX_FIELD_BYTES))
}

/// A bounded list of cleaned strings.
pub fn text_list<'a>(values: impl IntoIterator<Item = &'a str>, max: usize) -> Value {
    Value::Array(
        values
            .into_iter()
            .take(max.min(MAX_SUMMARY_LIST))
            .map(text_fact)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framing() -> RunFraming<'static> {
        RunFraming {
            provider_id: "test",
            historical: false,
            note: PASSIVE_NOTE,
            subject_facts: Map::new(),
            extra: Map::new(),
            provider_partial: false,
        }
    }

    #[test]
    fn names_are_canonicalized_and_scoped_to_the_subject() {
        let d = "example.test";
        assert_eq!(classify_name(d, "Example.Test."), NameClass::Subject);
        assert_eq!(
            classify_name(d, "API.example.test."),
            NameClass::Subdomain("api.example.test".into())
        );
        assert_eq!(
            classify_name(d, "badexample.test"),
            NameClass::OutOfDomain("badexample.test".into())
        );
        for bad in [
            "*.example.test",
            "a b.example.test",
            "",
            "-x.example.test",
            "x..example.test",
        ] {
            assert_eq!(classify_name(d, bad), NameClass::Invalid, "{bad}");
        }
    }

    #[test]
    fn findings_dedupe_bound_and_count_drops() {
        let mut f = DomainFindings::new("example.test");
        assert_eq!(
            f.add_host("api.example.test", Map::new()).as_deref(),
            Some("api.example.test")
        );
        f.add_host("API.EXAMPLE.TEST.", Map::new());
        f.add_host("example.test", Map::new());
        f.add_host("evil.test", Map::new());
        f.add_host("not a name", Map::new());
        f.add_email("person@example.test", Map::new());
        f.add_email("person@mail.example.test", Map::new());
        f.add_email("someone@other.test", Map::new());
        f.add_ip("192.0.2.10", Some("api.example.test"), Map::new());
        f.add_ip("192.0.2.11", Some("unknown.example.test"), Map::new());
        f.add_ip("999.1.1.1", None, Map::new());
        f.add_nameserver("ns1.dns-provider.test", Map::new());
        assert_eq!((f.host_count(), f.email_count(), f.ip_count()), (1, 2, 2));
        assert_eq!(f.dropped.out_of_domain, 2);
        assert_eq!(f.dropped.invalid, 2);
        for i in 0..(MAX_HOSTS + 5) {
            f.add_host(&format!("h{i}.example.test"), Map::new());
        }
        assert_eq!(f.host_count(), MAX_HOSTS);
        assert!(f.dropped.over_limit >= 5);

        let out = build_domain_output(f, framing());
        assert_eq!(out.summary.as_ref().unwrap()["subject_kind"], "DOMAIN");
        assert!(out.partial, "over-limit drops make the run partial");
        assert_eq!(out.discoveries[0].asset_type, AssetType::Domain);
        let ip = out
            .discoveries
            .iter()
            .find(|d| d.value == "192.0.2.10")
            .unwrap();
        assert_eq!(ip.source.as_deref(), Some("api.example.test"));
        assert_eq!(ip.relationship, Some(RelationshipType::ObservedIp));
        let orphan = out
            .discoveries
            .iter()
            .find(|d| d.value == "192.0.2.11")
            .unwrap();
        assert_eq!(orphan.source.as_deref(), Some("example.test"));
        let ns = out
            .discoveries
            .iter()
            .find(|d| d.relationship == Some(RelationshipType::HasNameserver))
            .unwrap();
        assert_eq!(ns.asset_type, AssetType::Hostname);
        let obs = ip.observation.as_ref().unwrap();
        assert_eq!(obs.confidence, "REPORTED");
        assert_eq!(obs.metadata["liveness"], "unverified");
        assert_eq!(obs.metadata["passive"], true);
    }
}
