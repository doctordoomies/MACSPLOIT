//! Native certificate-transparency lookup (built-in, passive) — Domain OSINT.
//!
//! One bounded HTTPS GET to crt.sh's public JSON search
//! (`https://crt.sh/?q=%25.<domain>&output=json`), which returns logged
//! certificates whose names fall under the domain. crt.sh is a public CT-log search
//! operated by Sectigo; it is the only host contacted. The subject domain and the
//! names found are never resolved or probed.
//!
//! Upstream record fields used (all untrusted): `name_value` (newline-separated
//! SAN/CN names), `common_name`, `not_before`, `not_after`, `issuer_name`, `id`.
//! Names are lowercased, trailing dots stripped, validated with the core's domain
//! normalizer, kept only inside the subject domain, and deduplicated across
//! certificates. `*.x` wildcards are kept as `x` with `wildcard: true` (a wildcard
//! for the subject itself is only counted). Email-address SANs are counted and
//! discarded (minimization).
//!
//! Semantics: a CT name is **historical** — a certificate once named the host. It
//! is not proof that the host exists, resolves, or is live; observations say so and
//! carry the certificate validity window so expired-only names are visible.
//!
//! Bounds: 90 s deadline, 4 MiB response (larger responses fail with
//! `BudgetExceeded` rather than parsing a truncated document), 20,000 records,
//! 250 kept names per run (the rest are counted; the run is partial). Raw bytes are
//! stored as evidence (1 MiB chunks) before parsing.

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
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

pub const CT_PROVIDER_ID: &str = "native_ct";
/// The single public CT search endpoint contacted.
pub const CT_SEARCH_BASE: &str = "https://crt.sh/";
pub const CT_TIMEOUT: Duration = Duration::from_secs(90);
pub const CT_BODY_CAP: usize = 4 * 1024 * 1024;
pub const CT_MAX_RECORDS: usize = 20_000;
const RESPONSE_ARTIFACT: &str = "ct_response";

pub struct NativeCtProvider {
    transport: Arc<dyn WebTransport>,
}

impl NativeCtProvider {
    pub fn new(transport: Arc<dyn WebTransport>) -> Self {
        Self { transport }
    }

    /// The exact query URL. `%25` is the URL-encoded `%` LIKE wildcard, so the
    /// search covers names *under* the domain. The domain is already a validated
    /// LDH name (letters, digits, hyphens, dots), so it needs no further encoding.
    pub fn query_url(domain: &str) -> String {
        format!("{CT_SEARCH_BASE}?q=%25.{domain}&output=json")
    }
}

/// Per-name aggregate across certificates.
#[derive(Default)]
struct NameAggregate {
    certificates: usize,
    wildcard: bool,
    first_not_before: Option<String>,
    last_not_after: Option<String>,
    issuers: BTreeSet<String>,
}

fn timestamp(record: &Map<String, Value>, key: &str) -> Option<String> {
    let value = record.get(key)?.as_str()?;
    // ISO-8601 (`YYYY-MM-DDTHH:MM:SS`); anything else is ignored.
    let value = value.get(..19).unwrap_or(value);
    (value.len() == 19
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '-' | ':' | 'T')))
    .then(|| value.to_owned())
}

struct CtParse {
    names: BTreeMap<String, NameAggregate>,
    records: usize,
    malformed: usize,
    records_dropped: usize,
    email_names: usize,
    wildcard_subject: usize,
}

fn parse_records(body: &[u8], domain: &str, findings: &mut DomainFindings) -> Result<CtParse> {
    let value: Value = serde_json::from_slice(body).map_err(|_| {
        CoreError::new(
            "ProviderFailure",
            "The certificate-transparency response is not valid JSON; raw output is preserved as evidence.",
        )
    })?;
    let Value::Array(records) = value else {
        return Err(CoreError::new(
            "ProviderFailure",
            "The certificate-transparency response is not a JSON array; raw output is preserved as evidence.",
        ));
    };
    let mut parse = CtParse {
        names: BTreeMap::new(),
        records: records.len(),
        malformed: 0,
        records_dropped: records.len().saturating_sub(CT_MAX_RECORDS),
        email_names: 0,
        wildcard_subject: 0,
    };
    for record in records.iter().take(CT_MAX_RECORDS) {
        let Some(record) = record.as_object() else {
            parse.malformed += 1;
            continue;
        };
        let mut raw_names: Vec<&str> = Vec::new();
        if let Some(names) = record.get("name_value").and_then(Value::as_str) {
            raw_names.extend(names.split('\n').take(1000));
        }
        if let Some(cn) = record.get("common_name").and_then(Value::as_str) {
            raw_names.push(cn);
        }
        if raw_names.is_empty() {
            parse.malformed += 1;
            continue;
        }
        let not_before = timestamp(record, "not_before");
        let not_after = timestamp(record, "not_after");
        let issuer = record
            .get("issuer_name")
            .and_then(Value::as_str)
            .map(|i| crate::osint::clean_text(i, 160));
        let mut seen_in_record = BTreeSet::new();
        for raw in raw_names {
            let raw = raw.trim().trim_end_matches('.').to_ascii_lowercase();
            if raw.is_empty() {
                continue;
            }
            if raw.contains('@') {
                parse.email_names += 1;
                continue;
            }
            let (name, wildcard) = match raw.strip_prefix("*.") {
                Some(base) => (base.to_owned(), true),
                None => (raw, false),
            };
            match domain::classify_name(domain, &name) {
                domain::NameClass::Subdomain(name) => {
                    if !seen_in_record.insert((name.clone(), wildcard)) {
                        continue;
                    }
                    let aggregate = parse.names.entry(name).or_default();
                    aggregate.certificates += 1;
                    aggregate.wildcard |= wildcard;
                    if let Some(nb) = &not_before {
                        if aggregate.first_not_before.as_ref().is_none_or(|f| nb < f) {
                            aggregate.first_not_before = Some(nb.clone());
                        }
                    }
                    if let Some(na) = &not_after {
                        if aggregate.last_not_after.as_ref().is_none_or(|l| na > l) {
                            aggregate.last_not_after = Some(na.clone());
                        }
                    }
                    if let Some(issuer) = &issuer {
                        if aggregate.issuers.len() < 3 {
                            aggregate.issuers.insert(issuer.clone());
                        }
                    }
                }
                domain::NameClass::Subject if wildcard => parse.wildcard_subject += 1,
                domain::NameClass::Subject => {}
                domain::NameClass::OutOfDomain(_) => findings.dropped.out_of_domain += 1,
                domain::NameClass::Invalid => findings.dropped.invalid += 1,
            }
        }
    }
    Ok(parse)
}

impl Provider for NativeCtProvider {
    fn metadata(&self) -> ProviderMetadata {
        ProviderMetadata {
            id: CT_PROVIDER_ID.into(),
            name: "Certificate Transparency (crt.sh)".into(),
            description: "Built-in passive certificate-transparency lookup: historical certificate names under one in-scope domain from crt.sh's public CT search. Names are never resolved or probed.".into(),
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
        CT_TIMEOUT
    }

    fn execute(
        &self,
        target: &str,
        capability: Capability,
        _inputs: &[Asset],
        ctx: &ProviderContext,
    ) -> Result<Execution> {
        let domain = passive_web::domain_subject(target, capability, "Certificate transparency")?;
        let mut log = RequestLog::new(CT_PROVIDER_ID, &domain);
        let url = Self::query_url(&domain);
        let (end, artifacts) =
            match self
                .transport
                .fetch_bounded(&url, ctx.deadline, ctx.cancelled, CT_BODY_CAP)
            {
                Err(error) => {
                    log.failure("ct_search", &url, &error);
                    (RunEnd::Error(error), Vec::new())
                }
                Ok((response, truncated)) => {
                    log.response("ct_search", &url, &response, truncated);
                    let artifacts = if response.body.is_empty() {
                        Vec::new()
                    } else {
                        passive_web::chunk_artifacts(RESPONSE_ARTIFACT, &response.body)
                    };
                    let end = match response.status {
                        _ if truncated => RunEnd::Completed("oversized"),
                        200 => RunEnd::Completed("ok"),
                        404 => RunEnd::Completed("not_found"),
                        _ => RunEnd::Failed("http_error"),
                    };
                    (end, artifacts)
                }
            };
        passive_web::execution(target, capability, &log, end, json!({}), artifacts)
    }

    fn parse(&self, execution: &Execution) -> Result<Vec<Discovery>> {
        Ok(self.parse_outcome(execution)?.discoveries)
    }

    fn parse_outcome(&self, execution: &Execution) -> Result<ParsedOutput> {
        let domain = passive_web::domain_subject(
            &execution.target,
            execution.capability,
            "Certificate transparency",
        )?;
        let report = passive_web::report(execution, "Certificate transparency")?;
        let mut findings = DomainFindings::new(&domain);
        let mut extra = Map::new();
        extra.insert("source".into(), json!("crt.sh"));
        let parse = match report["outcome"].as_str() {
            Some("oversized") => {
                return Err(CoreError::new(
                    "BudgetExceeded",
                    "The certificate-transparency response exceeded 4 MiB and was not parsed; the captured bytes are preserved as evidence. Try a narrower (sub)domain.",
                ))
            }
            Some("not_found") => None,
            Some("ok") => {
                let body = passive_web::body_from_artifacts(execution, RESPONSE_ARTIFACT)
                    .unwrap_or_default();
                if body.iter().all(u8::is_ascii_whitespace) {
                    None
                } else {
                    Some(parse_records(&body, &domain, &mut findings)?)
                }
            }
            _ => {
                return Err(CoreError::new(
                    "ProviderFailure",
                    "The certificate-transparency request did not complete.",
                ))
            }
        };
        let mut provider_partial = false;
        if let Some(parse) = parse {
            let now = crate::now();
            let now = now.get(..19).unwrap_or(&now).to_owned();
            for (name, aggregate) in parse.names {
                let mut facts = Map::new();
                facts.insert("certificates".into(), json!(aggregate.certificates));
                facts.insert("wildcard".into(), json!(aggregate.wildcard));
                if let Some(first) = aggregate.first_not_before {
                    facts.insert("first_not_before".into(), json!(first));
                }
                if let Some(last) = &aggregate.last_not_after {
                    facts.insert("last_not_after".into(), json!(last));
                    facts.insert("all_certificates_expired".into(), json!(*last < now));
                }
                facts.insert(
                    "issuers".into(),
                    domain::text_list(aggregate.issuers.iter().map(String::as_str), 3),
                );
                findings.add_host(&name, facts);
            }
            provider_partial = parse.malformed > 0 || parse.records_dropped > 0;
            extra.insert(
                "ct".into(),
                json!({
                    "records": parse.records,
                    "records_malformed": parse.malformed,
                    "records_dropped": parse.records_dropped,
                    "email_names_discarded": parse.email_names,
                    "wildcard_for_subject": parse.wildcard_subject,
                }),
            );
        } else {
            extra.insert("ct".into(), json!({"records": 0}));
        }
        Ok(domain::build_domain_output(
            findings,
            RunFraming {
                provider_id: CT_PROVIDER_ID,
                historical: true,
                note: domain::CT_NOTE,
                subject_facts: Map::new(),
                extra,
                provider_partial,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{assets::AssetType, web::StaticWebTransport};
    use std::{sync::atomic::AtomicBool, time::Instant};

    const URL: &str = "https://crt.sh/?q=%25.example.test&output=json";

    fn run(transport: StaticWebTransport, cancelled: bool) -> Execution {
        let provider = NativeCtProvider::new(Arc::new(transport));
        let tools = ToolConfig::default();
        let flag = AtomicBool::new(cancelled);
        let ctx = ProviderContext {
            cancelled: &flag,
            deadline: Instant::now() + Duration::from_secs(5),
            tools: &tools,
            scope: &[],
            options: &Value::Null,
        };
        provider
            .execute("example.test", Capability::DomainOsint, &[], &ctx)
            .unwrap()
    }

    fn parse(execution: &Execution) -> Result<ParsedOutput> {
        NativeCtProvider::new(Arc::new(StaticWebTransport::new())).parse_outcome(execution)
    }

    #[test]
    fn query_is_a_fixed_https_ct_search_for_names_under_the_domain() {
        assert_eq!(NativeCtProvider::query_url("example.test"), URL);
        let provider = NativeCtProvider::new(Arc::new(StaticWebTransport::new()));
        let meta = provider.metadata();
        assert_eq!(meta.risk_class, RiskClass::Passive);
        assert_eq!(meta.network_activity, NetworkActivity::Network);
        assert_eq!(meta.capabilities, vec![Capability::DomainOsint]);
    }

    #[test]
    fn records_normalize_dedupe_flag_wildcards_and_stay_in_domain() {
        let body = r#"[
          {"id":1,"name_value":"API.example.test\n*.dev.example.test\n*.example.test\nops@example.test","common_name":"api.example.test.","not_before":"2020-01-01T00:00:00","not_after":"2020-04-01T00:00:00","issuer_name":"C=US, O=Example CA"},
          {"id":2,"name_value":"api.example.test\nold.example.test\nexample.test\nevil.test","common_name":"api.example.test","not_before":"2025-01-01T00:00:00","not_after":"2099-01-01T00:00:00","issuer_name":"C=US, O=Example CA"},
          "garbage",
          {"id":3}
        ]"#;
        let exec = run(
            StaticWebTransport::new().with_response(URL, 200, &[], body),
            false,
        );
        assert_eq!(exec.exit_status, Some(0));
        assert_eq!(exec.artifacts.len(), 1);
        let out = parse(&exec).unwrap();
        let names: Vec<_> = out
            .discoveries
            .iter()
            .filter(|d| d.asset_type == AssetType::Subdomain)
            .map(|d| d.value.as_str())
            .collect();
        assert_eq!(
            names,
            ["api.example.test", "dev.example.test", "old.example.test"]
        );
        let api = out
            .discoveries
            .iter()
            .find(|d| d.value == "api.example.test")
            .unwrap();
        let meta = &api.observation.as_ref().unwrap().metadata;
        assert_eq!(meta["historical"], true);
        assert_eq!(meta["facts"]["certificates"], 2);
        assert_eq!(meta["facts"]["first_not_before"], "2020-01-01T00:00:00");
        assert_eq!(meta["facts"]["all_certificates_expired"], false);
        let dev = out
            .discoveries
            .iter()
            .find(|d| d.value == "dev.example.test")
            .unwrap();
        assert_eq!(
            dev.observation.as_ref().unwrap().metadata["facts"]["wildcard"],
            true
        );
        let summary = out.summary.unwrap();
        assert_eq!(summary["ct"]["email_names_discarded"], 1);
        assert_eq!(summary["ct"]["wildcard_for_subject"], 1);
        assert_eq!(summary["ct"]["records_malformed"], 2);
        assert_eq!(summary["counts"]["dropped_out_of_domain"], 1);
        assert!(out.partial, "malformed records make the run partial");
        // No email or IP assets are ever produced from CT.
        assert!(out
            .discoveries
            .iter()
            .all(|d| matches!(d.asset_type, AssetType::Domain | AssetType::Subdomain)));
    }

    #[test]
    fn empty_and_not_found_are_clean_zero_results() {
        for (status, body) in [(200, "[]"), (200, ""), (404, "")] {
            let exec = run(
                StaticWebTransport::new().with_response(URL, status, &[], body),
                false,
            );
            let out = parse(&exec).unwrap();
            assert_eq!(out.discoveries.len(), 1, "only the subject");
            assert!(!out.partial);
        }
    }

    #[test]
    fn failures_keep_the_request_log_and_map_to_codes() {
        let exec = run(
            StaticWebTransport::new().with_response(URL, 502, &[], "bad gateway"),
            false,
        );
        assert_eq!(exec.exit_status, Some(1));
        assert!(String::from_utf8_lossy(&exec.stdout).contains("\"status\": 502"));
        let exec = run(StaticWebTransport::new().with_timeout(URL), false);
        assert!(exec.timed_out);
        let exec = run(StaticWebTransport::new().with_failure(URL, "tls"), false);
        assert_eq!(exec.exit_status, Some(1));
        let exec = run(StaticWebTransport::new(), true);
        assert!(exec.cancelled);
        // Malformed JSON and a non-array document are parser failures.
        for body in ["{not json", "{\"a\":1}"] {
            let exec = run(
                StaticWebTransport::new().with_response(URL, 200, &[], body),
                false,
            );
            assert_eq!(parse(&exec).unwrap_err().code, "ProviderFailure");
        }
    }

    #[test]
    fn oversized_responses_are_refused_not_truncated() {
        let big = format!("[{}]", "\"x\",".repeat(CT_BODY_CAP / 4 + 10));
        let exec = run(
            StaticWebTransport::new().with_response(URL, 200, &[], &big),
            false,
        );
        assert!(
            exec.artifacts.len() >= 4,
            "captured bytes kept as chunked evidence"
        );
        assert!(exec
            .artifacts
            .iter()
            .all(|a| a.bytes.len() <= passive_web::EVIDENCE_CHUNK));
        assert_eq!(parse(&exec).unwrap_err().code, "BudgetExceeded");
    }

    #[test]
    fn non_domain_capabilities_are_rejected() {
        let provider = NativeCtProvider::new(Arc::new(StaticWebTransport::new()));
        let tools = ToolConfig::default();
        let flag = AtomicBool::new(false);
        let ctx = ProviderContext {
            cancelled: &flag,
            deadline: Instant::now() + Duration::from_secs(5),
            tools: &tools,
            scope: &[],
            options: &Value::Null,
        };
        let err = provider
            .execute("example.test", Capability::SubdomainDiscovery, &[], &ctx)
            .map(|_| ())
            .unwrap_err();
        assert_eq!(err.code, "ProviderUnsupported");
    }
}
