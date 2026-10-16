//! Native RDAP registration lookup (built-in, passive) — Domain OSINT.
//!
//! RDAP (RFC 9082/9083) is the registries' structured, HTTPS successor to WHOIS.
//! The client:
//!
//! 1. Fetches IANA's DNS bootstrap registry (RFC 9224,
//!    `https://data.iana.org/rdap/dns.json`, ≤ 512 KiB) and picks the
//!    authoritative RDAP base URL for the domain's longest matching TLD/suffix.
//!    Only `https` base URLs are used.
//! 2. Sends one `GET <base>/domain/<domain>` (≤ 1 MiB). Redirects are followed
//!    manually, at most two, and only to `https` hosts that appear in the IANA
//!    bootstrap file — never to arbitrary URLs. `related` links in the response
//!    (e.g. a registrar's RDAP server) are recorded but never followed.
//!
//! The subject domain itself is never contacted. RDAP queries registered names: a
//! subdomain target usually returns 404 (reported as "not found at the registry").
//!
//! Minimization: the run summary keeps only registration facts — ldhName, handle,
//! status values, event dates, nameservers, DNSSEC delegation flag, port43, and the
//! registrar's name and IANA ID. Registrant/admin/tech/billing contact details
//! (vCards: names, emails, phones, addresses) are never copied into observations;
//! only role counts are kept. The raw response is preserved as evidence.

use super::passive_web::{self, RequestLog, RunEnd};
use super::{
    Capability, Execution, NetworkActivity, ParsedOutput, Provider, ProviderContext,
    ProviderMetadata, RiskClass,
};
use crate::{
    assets::{Asset, Discovery},
    error::{CoreError, Result},
    osint::domain::{self, DomainFindings, RunFraming},
    process::{Installation, ToolConfig},
    targets::TargetType,
    web::WebTransport,
};
use serde_json::{json, Map, Value};
use std::{collections::BTreeSet, sync::Arc, time::Duration};

pub const RDAP_PROVIDER_ID: &str = "native_rdap";
pub const IANA_DNS_BOOTSTRAP: &str = "https://data.iana.org/rdap/dns.json";
pub const RDAP_TIMEOUT: Duration = Duration::from_secs(60);
pub const BOOTSTRAP_CAP: usize = 512 * 1024;
pub const RDAP_BODY_CAP: usize = 1024 * 1024;
pub const MAX_REDIRECTS: usize = 2;
const RESPONSE_ARTIFACT: &str = "rdap_response";
const BOOTSTRAP_ARTIFACT: &str = "rdap_bootstrap";
const MAX_LIST: usize = 16;

pub struct NativeRdapProvider {
    transport: Arc<dyn WebTransport>,
}

/// The server chosen from the bootstrap registry, plus every bootstrap-listed
/// https host (the only hosts a redirect may lead to).
#[derive(Debug, PartialEq, Eq)]
pub struct Bootstrap {
    pub base: String,
    pub matched_suffix: String,
    pub allowed_hosts: BTreeSet<String>,
}

/// Select the RDAP base URL for `domain` from an IANA DNS bootstrap document.
pub fn select_server(document: &[u8], domain: &str) -> Result<Option<Bootstrap>> {
    let malformed = || {
        CoreError::new(
            "ProviderFailure",
            "The IANA RDAP bootstrap registry is malformed.",
        )
    };
    let value: Value = serde_json::from_slice(document).map_err(|_| malformed())?;
    let services = value
        .get("services")
        .and_then(Value::as_array)
        .ok_or_else(malformed)?;
    let mut allowed_hosts = BTreeSet::new();
    let mut best: Option<(usize, String, String)> = None;
    for service in services.iter().take(5000) {
        let Some([suffixes, urls]) = service.as_array().map(Vec::as_slice) else {
            continue;
        };
        let urls: Vec<url::Url> = urls
            .as_array()
            .map(|u| {
                u.iter()
                    .take(8)
                    .filter_map(Value::as_str)
                    .filter_map(passive_web::https_url)
                    .collect()
            })
            .unwrap_or_default();
        for url in &urls {
            if let Some(host) = url.host_str() {
                allowed_hosts.insert(host.to_ascii_lowercase());
            }
        }
        let Some(base) = urls.first() else { continue };
        for suffix in suffixes.as_array().into_iter().flatten().take(2000) {
            let Some(suffix) = suffix.as_str().map(str::to_ascii_lowercase) else {
                continue;
            };
            let matches = domain == suffix || domain.ends_with(&format!(".{suffix}"));
            let labels = suffix.split('.').count();
            if matches && best.as_ref().is_none_or(|(n, _, _)| labels > *n) {
                best = Some((labels, suffix, base.to_string()));
            }
        }
    }
    Ok(best.map(|(_, matched_suffix, base)| Bootstrap {
        base,
        matched_suffix,
        allowed_hosts,
    }))
}

/// `<base>/domain/<domain>` with exactly one slash between parts.
pub fn domain_url(base: &str, domain: &str) -> String {
    format!("{}/domain/{domain}", base.trim_end_matches('/'))
}

impl NativeRdapProvider {
    pub fn new(transport: Arc<dyn WebTransport>) -> Self {
        Self { transport }
    }
}

fn strings(value: Option<&Value>, max: usize) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .take(max)
                .map(|s| crate::osint::clean_text(s, 128))
                .collect()
        })
        .unwrap_or_default()
}

/// The registrar's display name from a jCard (`["vcard", [["fn", {}, "text", "Name"], …]]`).
fn vcard_fn(entity: &Map<String, Value>) -> Option<String> {
    let properties = entity.get("vcardArray")?.as_array()?.get(1)?.as_array()?;
    properties.iter().take(64).find_map(|p| {
        let p = p.as_array()?;
        (p.first()?.as_str()? == "fn")
            .then(|| p.get(3)?.as_str().map(|s| crate::osint::clean_text(s, 160)))?
    })
}

/// Extract the minimized registration facts and nameservers from an RDAP domain
/// object. Returns (facts, nameservers, ldh-name mismatch).
fn registration(
    object: &Map<String, Value>,
    domain: &str,
) -> (Map<String, Value>, Vec<String>, bool) {
    let mut facts = Map::new();
    facts.insert("found".into(), json!(true));
    let ldh = object
        .get("ldhName")
        .and_then(Value::as_str)
        .map(|s| s.trim_end_matches('.').to_ascii_lowercase());
    let mismatch = ldh.as_deref().is_some_and(|l| l != domain);
    if let Some(ldh) = &ldh {
        facts.insert("ldh_name".into(), json!(crate::osint::clean_text(ldh, 253)));
    }
    if let Some(handle) = object.get("handle").and_then(Value::as_str) {
        facts.insert(
            "handle".into(),
            json!(crate::osint::clean_text(handle, 128)),
        );
    }
    facts.insert(
        "status".into(),
        json!(strings(object.get("status"), MAX_LIST)),
    );
    let events: Vec<Value> = object
        .get("events")
        .and_then(Value::as_array)
        .map(|events| {
            events
                .iter()
                .take(MAX_LIST)
                .filter_map(|e| {
                    let action = e.get("eventAction")?.as_str()?;
                    let date = e.get("eventDate")?.as_str()?;
                    Some(json!({
                        "action": crate::osint::clean_text(action, 64),
                        "date": crate::osint::clean_text(date, 40),
                    }))
                })
                .collect()
        })
        .unwrap_or_default();
    facts.insert("events".into(), json!(events));
    if let Some(signed) = object
        .get("secureDNS")
        .and_then(|s| s.get("delegationSigned"))
        .and_then(Value::as_bool)
    {
        facts.insert("dnssec_delegation_signed".into(), json!(signed));
    }
    if let Some(port43) = object.get("port43").and_then(Value::as_str) {
        facts.insert(
            "port43".into(),
            json!(crate::osint::clean_text(port43, 253)),
        );
    }
    let mut roles: Map<String, Value> = Map::new();
    for entity in object
        .get("entities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(64)
        .filter_map(Value::as_object)
    {
        let entity_roles = strings(entity.get("roles"), 8);
        for role in &entity_roles {
            let count = roles.entry(role.clone()).or_insert(json!(0));
            *count = json!(count.as_u64().unwrap_or(0) + 1);
        }
        if entity_roles.iter().any(|r| r == "registrar") && !facts.contains_key("registrar") {
            let iana_id = entity
                .get("publicIds")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .find(|p| p.get("type").and_then(Value::as_str) == Some("IANA Registrar ID"))
                .and_then(|p| p.get("identifier")?.as_str())
                .map(|s| crate::osint::clean_text(s, 32));
            facts.insert(
                "registrar".into(),
                json!({"name": vcard_fn(entity), "iana_id": iana_id}),
            );
        }
    }
    // Contact roles are counted only; their vCards are never copied.
    facts.insert("entity_roles".into(), Value::Object(roles));
    let related: Vec<String> = object
        .get("links")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|l| l.get("rel").and_then(Value::as_str) == Some("related"))
        .filter_map(|l| l.get("href")?.as_str())
        .filter(|h| passive_web::https_url(h).is_some())
        .take(4)
        .map(|h| crate::osint::clean_text(h, 512))
        .collect();
    facts.insert("related_links_not_followed".into(), json!(related));
    let nameservers = object
        .get("nameservers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(domain::MAX_NAMESERVERS * 2)
        .filter_map(|n| n.get("ldhName")?.as_str().map(str::to_owned))
        .collect();
    (facts, nameservers, mismatch)
}

impl Provider for NativeRdapProvider {
    fn metadata(&self) -> ProviderMetadata {
        ProviderMetadata {
            id: RDAP_PROVIDER_ID.into(),
            name: "RDAP Registration (native)".into(),
            description: "Built-in passive RDAP lookup: registration status, dates, registrar, and nameservers for one in-scope domain from its registry (via IANA's bootstrap). Contact details are not copied; the domain is never contacted.".into(),
            version: "built-in".into(),
            capabilities: vec![Capability::DomainOsint],
            supported_target_types: vec![TargetType::Domain],
            risk_class: RiskClass::Passive,
            network_activity: NetworkActivity::Network,
        }
    }

    fn installation(&self, _tools: &ToolConfig) -> Installation {
        Installation::BuiltIn
    }

    fn timeout(&self) -> Duration {
        RDAP_TIMEOUT
    }

    fn execute(
        &self,
        target: &str,
        capability: Capability,
        _inputs: &[Asset],
        ctx: &ProviderContext,
    ) -> Result<Execution> {
        let domain = passive_web::domain_subject(target, capability, "RDAP")?;
        let mut log = RequestLog::new(RDAP_PROVIDER_ID, &domain);
        let mut artifacts = Vec::new();
        let finish = |log: &RequestLog, end, extra, artifacts| {
            passive_web::execution(target, capability, log, end, extra, artifacts)
        };

        // 1. Bootstrap.
        let bootstrap = match self.transport.fetch_bounded(
            IANA_DNS_BOOTSTRAP,
            ctx.deadline,
            ctx.cancelled,
            BOOTSTRAP_CAP,
        ) {
            Err(error) => {
                log.failure("iana_bootstrap", IANA_DNS_BOOTSTRAP, &error);
                return finish(&log, RunEnd::Error(error), json!({}), artifacts);
            }
            Ok((response, truncated)) => {
                log.response("iana_bootstrap", IANA_DNS_BOOTSTRAP, &response, truncated);
                if response.status != 200 || truncated {
                    log.note("IANA bootstrap unavailable or oversized");
                    return finish(
                        &log,
                        RunEnd::Failed("bootstrap_error"),
                        json!({}),
                        artifacts,
                    );
                }
                let selected = select_server(&response.body, &domain);
                artifacts.push(super::ExecutionArtifact {
                    name: BOOTSTRAP_ARTIFACT.into(),
                    observed_bytes: Some(response.body.len() as u64),
                    bytes: response.body,
                    over_limit: false,
                });
                match selected {
                    Err(_) => {
                        log.note("IANA bootstrap malformed");
                        return finish(
                            &log,
                            RunEnd::Failed("bootstrap_error"),
                            json!({}),
                            artifacts,
                        );
                    }
                    Ok(None) => {
                        log.note("no RDAP service is registered for this TLD");
                        return finish(
                            &log,
                            RunEnd::Completed("no_rdap_service"),
                            json!({}),
                            artifacts,
                        );
                    }
                    Ok(Some(bootstrap)) => bootstrap,
                }
            }
        };
        let server = json!({"base": bootstrap.base, "matched_suffix": bootstrap.matched_suffix});

        // 2. Domain query with bounded, allow-listed redirects.
        let mut url = domain_url(&bootstrap.base, &domain);
        for hop in 0..=MAX_REDIRECTS {
            let (response, truncated) =
                match self
                    .transport
                    .fetch_bounded(&url, ctx.deadline, ctx.cancelled, RDAP_BODY_CAP)
                {
                    Ok(pair) => pair,
                    Err(error) => {
                        log.failure("rdap_domain", &url, &error);
                        return finish(
                            &log,
                            RunEnd::Error(error),
                            json!({"server": server}),
                            artifacts,
                        );
                    }
                };
            log.response("rdap_domain", &url, &response, truncated);
            if matches!(response.status, 301 | 302 | 303 | 307 | 308) {
                let next = response
                    .header("location")
                    .and_then(|location| url::Url::parse(&url).ok()?.join(location).ok())
                    .filter(|next| passive_web::https_url(next.as_str()).is_some())
                    .filter(|next| {
                        next.host_str().is_some_and(|h| {
                            bootstrap.allowed_hosts.contains(&h.to_ascii_lowercase())
                        })
                    });
                match next {
                    Some(next) if hop < MAX_REDIRECTS => {
                        url = next.to_string();
                        continue;
                    }
                    Some(_) => log.note("redirect limit reached; not followed"),
                    None => log.note(
                        "redirect to a host outside the IANA RDAP bootstrap (or non-https) refused",
                    ),
                }
                return finish(
                    &log,
                    RunEnd::Failed("redirect_refused"),
                    json!({"server": server}),
                    artifacts,
                );
            }
            let end = match response.status {
                _ if truncated => RunEnd::Completed("oversized"),
                200 => RunEnd::Completed("ok"),
                404 => RunEnd::Completed("not_found"),
                _ => RunEnd::Failed("http_error"),
            };
            if !response.body.is_empty() {
                let mut response_artifacts =
                    passive_web::chunk_artifacts(RESPONSE_ARTIFACT, &response.body);
                // The registry response is the primary evidence for observations.
                response_artifacts.append(&mut artifacts);
                artifacts = response_artifacts;
            }
            return finish(&log, end, json!({"server": server}), artifacts);
        }
        unreachable!("the redirect loop always returns")
    }

    fn parse(&self, execution: &Execution) -> Result<Vec<Discovery>> {
        Ok(self.parse_outcome(execution)?.discoveries)
    }

    fn parse_outcome(&self, execution: &Execution) -> Result<ParsedOutput> {
        let domain = passive_web::domain_subject(&execution.target, execution.capability, "RDAP")?;
        let report = passive_web::report(execution, "RDAP")?;
        let mut findings = DomainFindings::new(&domain);
        let mut extra = Map::new();
        extra.insert("source".into(), json!("rdap"));
        if let Some(server) = report.get("server") {
            extra.insert("rdap_server".into(), server.clone());
        }
        let mut provider_partial = false;
        let facts = match report["outcome"].as_str() {
            Some("oversized") => {
                return Err(CoreError::new(
                    "BudgetExceeded",
                    "The RDAP response exceeded 1 MiB and was not parsed; the captured bytes are preserved as evidence.",
                ))
            }
            Some("no_rdap_service") => json!({"found": false, "reason": "no RDAP service is registered for this TLD"}),
            Some("not_found") => json!({"found": false, "reason": "not found at the registry (RDAP answers for registered domains; a subdomain is usually not found)"}),
            Some("ok") => {
                let body = passive_web::body_from_artifacts(execution, RESPONSE_ARTIFACT)
                    .unwrap_or_default();
                let value: Value = serde_json::from_slice(&body).map_err(|_| {
                    CoreError::new(
                        "ProviderFailure",
                        "The RDAP response is not valid JSON; raw output is preserved as evidence.",
                    )
                })?;
                let object = value.as_object().ok_or_else(|| {
                    CoreError::new(
                        "ProviderFailure",
                        "The RDAP response is not a JSON object; raw output is preserved as evidence.",
                    )
                })?;
                let (facts, nameservers, mismatch) = registration(object, &domain);
                for nameserver in nameservers {
                    findings.add_nameserver(&nameserver, Map::new());
                }
                if mismatch {
                    // The registry answered for a different name: keep it as evidence
                    // but treat the run as partial so it is reviewed.
                    provider_partial = true;
                }
                Value::Object(facts)
            }
            _ => {
                return Err(CoreError::new(
                    "ProviderFailure",
                    "The RDAP lookup did not complete.",
                ))
            }
        };
        let Value::Object(subject_facts) = facts else {
            unreachable!("facts are always an object")
        };
        Ok(domain::build_domain_output(
            findings,
            RunFraming {
                provider_id: RDAP_PROVIDER_ID,
                historical: false,
                note: domain::PASSIVE_NOTE,
                subject_facts,
                extra,
                provider_partial,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        assets::{AssetType, RelationshipType},
        web::StaticWebTransport,
    };
    use std::{sync::atomic::AtomicBool, time::Instant};

    pub const BOOTSTRAP: &str = r#"{"version":"1.0","services":[
        [["test"],["https://rdap.registry.test/v1/"]],
        [["co.test"],["http://insecure.registry.test/","https://rdap.co-registry.test/"]],
        [["other"],["https://rdap.other.test/"]]
    ]}"#;
    const QUERY: &str = "https://rdap.registry.test/v1/domain/example.test";

    pub const RESPONSE: &str = r#"{
      "objectClassName":"domain","handle":"EX-1","ldhName":"EXAMPLE.TEST",
      "status":["client transfer prohibited","active"],
      "events":[{"eventAction":"registration","eventDate":"2001-02-03T04:05:06Z"},{"eventAction":"expiration","eventDate":"2031-02-03T04:05:06Z"}],
      "secureDNS":{"delegationSigned":false},
      "port43":"whois.registry.test",
      "nameservers":[{"objectClassName":"nameserver","ldhName":"NS1.DNS-HOST.TEST"},{"objectClassName":"nameserver","ldhName":"ns2.example.test"}],
      "entities":[
        {"objectClassName":"entity","roles":["registrar"],"publicIds":[{"type":"IANA Registrar ID","identifier":"9999"}],
         "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Example Registrar LLC"]]],
         "entities":[{"roles":["abuse"],"vcardArray":["vcard",[["email",{},"text","abuse@registrar.test"]]]}]},
        {"objectClassName":"entity","roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Private Person"],["email",{},"text","owner@example.test"],["tel",{},"text","+1.2025550143"]]]}
      ],
      "links":[{"rel":"related","href":"https://rdap.registrar.test/domain/example.test"},{"rel":"self","href":"https://rdap.registry.test/v1/domain/example.test"}]
    }"#;

    fn ctx_run(transport: StaticWebTransport, target: &str) -> Execution {
        let provider = NativeRdapProvider::new(Arc::new(transport));
        let tools = ToolConfig::default();
        let flag = AtomicBool::new(false);
        let ctx = ProviderContext {
            cancelled: &flag,
            deadline: Instant::now() + Duration::from_secs(5),
            tools: &tools,
            scope: &[],
            options: &Value::Null,
        };
        provider
            .execute(target, Capability::DomainOsint, &[], &ctx)
            .unwrap()
    }

    fn parse(execution: &Execution) -> Result<ParsedOutput> {
        NativeRdapProvider::new(Arc::new(StaticWebTransport::new())).parse_outcome(execution)
    }

    fn base() -> StaticWebTransport {
        StaticWebTransport::new().with_response(IANA_DNS_BOOTSTRAP, 200, &[], BOOTSTRAP)
    }

    #[test]
    fn bootstrap_selects_longest_https_suffix() {
        let b = select_server(BOOTSTRAP.as_bytes(), "example.test")
            .unwrap()
            .unwrap();
        assert_eq!(b.base, "https://rdap.registry.test/v1/");
        let b = select_server(BOOTSTRAP.as_bytes(), "shop.co.test")
            .unwrap()
            .unwrap();
        assert_eq!(
            (b.matched_suffix.as_str(), b.base.as_str()),
            ("co.test", "https://rdap.co-registry.test/")
        );
        assert!(!b.allowed_hosts.contains("insecure.registry.test"));
        assert!(select_server(BOOTSTRAP.as_bytes(), "example.invalid")
            .unwrap()
            .is_none());
        assert!(select_server(b"{}", "example.test").is_err());
        assert_eq!(
            domain_url("https://r.test/v1/", "example.test"),
            QUERY.replace("rdap.registry", "r")
        );
    }

    #[test]
    fn registration_facts_are_minimized_and_nameservers_linked() {
        let exec = ctx_run(
            base().with_response(QUERY, 200, &[], RESPONSE),
            "example.test",
        );
        assert_eq!(exec.exit_status, Some(0));
        assert_eq!(
            exec.artifacts[0].name, "rdap_response",
            "registry response is primary evidence"
        );
        let out = parse(&exec).unwrap();
        assert!(!out.partial);
        let summary = out.summary.unwrap();
        let reg = &summary["registration"];
        assert_eq!(reg["found"], true);
        assert_eq!(reg["registrar"]["name"], "Example Registrar LLC");
        assert_eq!(reg["registrar"]["iana_id"], "9999");
        assert_eq!(reg["entity_roles"]["registrant"], 1);
        assert_eq!(reg["events"][0]["action"], "registration");
        assert_eq!(
            reg["related_links_not_followed"][0],
            "https://rdap.registrar.test/domain/example.test"
        );
        // Contact details never reach normalized results.
        let text = summary.to_string();
        for contact in [
            "Private Person",
            "owner@example.test",
            "2025550143",
            "abuse@registrar.test",
        ] {
            assert!(
                !text.contains(contact),
                "contact detail leaked into the summary"
            );
        }
        let ns: Vec<_> = out
            .discoveries
            .iter()
            .filter(|d| d.relationship == Some(RelationshipType::HasNameserver))
            .map(|d| (d.asset_type, d.value.as_str()))
            .collect();
        assert_eq!(
            ns,
            [
                (AssetType::Hostname, "ns1.dns-host.test"),
                (AssetType::Subdomain, "ns2.example.test")
            ]
        );
        // Only the bootstrap and the registry were contacted.
        let log = String::from_utf8_lossy(&exec.stdout);
        assert!(
            !log.contains("rdap.registrar.test/domain\""),
            "related link not fetched"
        );
    }

    #[test]
    fn not_found_and_unknown_tld_are_clean_zero_results() {
        let exec = ctx_run(base().with_response(QUERY, 404, &[], ""), "example.test");
        let out = parse(&exec).unwrap();
        assert_eq!(out.summary.unwrap()["registration"]["found"], false);
        let exec = ctx_run(base(), "example.invalid");
        let out = parse(&exec).unwrap();
        assert_eq!(out.discoveries.len(), 1);
    }

    #[test]
    fn redirects_only_to_bootstrap_listed_https_hosts() {
        let allowed = "https://rdap.other.test/domain/example.test";
        let exec = ctx_run(
            base()
                .with_response(QUERY, 302, &[("Location", allowed)], "")
                .with_response(allowed, 200, &[], RESPONSE),
            "example.test",
        );
        assert!(parse(&exec).is_ok());
        for location in [
            "https://attacker.test/domain/example.test",
            "http://rdap.other.test/domain/example.test",
            "file:///etc/passwd",
        ] {
            let exec = ctx_run(
                base().with_response(QUERY, 302, &[("Location", location)], ""),
                "example.test",
            );
            assert_eq!(exec.exit_status, Some(1), "{location}");
            assert!(String::from_utf8_lossy(&exec.stdout).contains("redirect_refused"));
        }
        // Redirect loops stop at the bound.
        let exec = ctx_run(
            base()
                .with_response(QUERY, 302, &[("Location", allowed)], "")
                .with_response(allowed, 302, &[("Location", QUERY)], ""),
            "example.test",
        );
        assert_eq!(exec.exit_status, Some(1));
    }

    #[test]
    fn malformed_oversized_timeout_and_mismatch() {
        let exec = ctx_run(
            base().with_response(QUERY, 200, &[], "{nope"),
            "example.test",
        );
        assert_eq!(parse(&exec).unwrap_err().code, "ProviderFailure");
        let exec = ctx_run(
            base().with_response(QUERY, 200, &[], "[1,2]"),
            "example.test",
        );
        assert_eq!(parse(&exec).unwrap_err().code, "ProviderFailure");
        let big = format!("{{\"x\":\"{}\"}}", "a".repeat(RDAP_BODY_CAP));
        let exec = ctx_run(base().with_response(QUERY, 200, &[], &big), "example.test");
        assert_eq!(parse(&exec).unwrap_err().code, "BudgetExceeded");
        let exec = ctx_run(base().with_timeout(QUERY), "example.test");
        assert!(exec.timed_out);
        let exec = ctx_run(
            StaticWebTransport::new().with_timeout(IANA_DNS_BOOTSTRAP),
            "example.test",
        );
        assert!(exec.timed_out);
        let exec = ctx_run(
            StaticWebTransport::new().with_response(IANA_DNS_BOOTSTRAP, 200, &[], "{}"),
            "example.test",
        );
        assert_eq!(exec.exit_status, Some(1));
        let other = RESPONSE.replace("EXAMPLE.TEST", "OTHER.TEST");
        let exec = ctx_run(
            base().with_response(QUERY, 200, &[], &other),
            "example.test",
        );
        assert!(parse(&exec).unwrap().partial, "ldhName mismatch is partial");
    }
}
