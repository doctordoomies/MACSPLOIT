//! Shared OSINT primitives (Milestone 6.0).
//!
//! Provider-neutral building blocks used by username/email OSINT providers:
//!
//! * **Subject validation** — an OSINT subject is an explicitly added `Username` or
//!   `EmailAddress` target. It is an identifier, not a network destination; it is
//!   validated strictly here so it can never be interpreted as a provider option,
//!   a pattern/permutation expression, or shell syntax.
//! * **Check normalization** — every per-platform result is reduced to an
//!   [`OsintCheck`] with a provider-neutral [`CheckStatus`] (positive / negative /
//!   blocked / error / unknown) while the upstream status label is preserved.
//! * **Graph mapping** — [`build_output`] turns checks into the shared asset model:
//!   the subject (`Username`/`EmailAddress`), one `Account` per positive platform
//!   result (`has_account`), and an optional profile `URL` (`profile_url`). Per-run
//!   facts (upstream status, platform, bounded public profile fields) live on the
//!   observation, never on the deduplicated canonical asset.
//!
//! Identity rule: a positive result means "the provider reported this identifier on
//! this platform". It is not proof that two accounts belong to the same person, and
//! nothing here merges or correlates accounts.
//!
//! Everything a provider returns is untrusted: strings are stripped of control and
//! bidirectional-override characters and bounded; URLs must be plain HTTP(S) without
//! credentials; record, field, key, and list counts are capped.

use crate::{
    assets::{AssetType, Discovery, ObservationDetail, RelationshipType},
    error::{CoreError, Result},
    providers::ParsedOutput,
    targets::TargetType,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashSet};

/// Maximum upstream records considered from one run (the rest are counted as dropped).
pub const MAX_RECORDS: usize = 5000;
/// Maximum positive results normalized into Account assets from one run.
pub const MAX_POSITIVE: usize = 250;
/// Maximum bytes for one untrusted string field (platform, reason, metadata value).
pub const MAX_FIELD_BYTES: usize = 512;
/// Maximum bytes for one untrusted URL.
pub const MAX_URL_BYTES: usize = 2048;
/// Maximum public-profile metadata keys kept per result.
pub const MAX_METADATA_KEYS: usize = 24;
/// Maximum bytes for a metadata key.
pub const MAX_KEY_BYTES: usize = 64;
/// Maximum error/blocked/unknown entries listed in a run summary (all are counted).
pub const MAX_SUMMARY_LIST: usize = 100;

/// Confidence recorded on an OSINT observation: the provider reported it and
/// MACSPLOIT has not independently verified it.
pub const CONFIDENCE_REPORTED: &str = "REPORTED";

/// Shown with every OSINT summary so the uncertainty travels with the data.
pub const IDENTITY_NOTE: &str = "A provider reporting the same username or email on several platforms is not proof that those accounts belong to one person.";

/// Which kind of identifier an OSINT run is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SubjectKind {
    Username,
    Email,
}

/// A validated OSINT subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    pub kind: SubjectKind,
    /// The canonical asset identity (`@handle` or `local@domain`).
    pub canonical: String,
    /// The bare identifier handed to a provider (`handle` or `local@domain`).
    pub query: String,
}

impl Subject {
    /// Build a subject from a stored target. Only `Username` and `EmailAddress`
    /// targets are OSINT subjects.
    pub fn from_target(kind: TargetType, normalized: &str) -> Result<Self> {
        match kind {
            TargetType::Username => {
                let canonical = username_identity(normalized)?;
                let query = canonical.trim_start_matches('@').to_owned();
                Ok(Self {
                    kind: SubjectKind::Username,
                    canonical,
                    query,
                })
            }
            TargetType::EmailAddress => {
                let canonical = email_identity(normalized)?;
                Ok(Self {
                    kind: SubjectKind::Email,
                    query: canonical.clone(),
                    canonical,
                })
            }
            _ => Err(CoreError::new(
                "InvalidTarget",
                "OSINT requires a username or email target.",
            )),
        }
    }

    pub fn asset_type(&self) -> AssetType {
        match self.kind {
            SubjectKind::Username => AssetType::Username,
            SubjectKind::Email => AssetType::EmailAddress,
        }
    }
}

fn invalid_subject(message: &str) -> CoreError {
    CoreError::new("InvalidTarget", message)
}

/// Canonical `@handle` identity. Accepts `handle` or `@handle`. Only ASCII
/// letters, digits, `_`, `-`, and `.` are allowed (1–64 chars), and the handle may
/// not begin with `-` or `.`, so it can never be read as a provider option, a
/// pattern/permutation expression (`[`, `]`, `\`, `{`), or a path.
pub fn username_identity(value: &str) -> Result<String> {
    let handle = value.strip_prefix('@').unwrap_or(value);
    if handle.is_empty()
        || handle.len() > 64
        || handle.starts_with(['-', '.'])
        || !handle
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err(invalid_subject(
            "A username may contain only letters, digits, '_', '-', and '.' (1-64 characters, not starting with '-' or '.').",
        ));
    }
    Ok(format!("@{handle}"))
}

/// Canonical email identity (`local@domain`, domain lowercased, local part kept).
/// Stricter than general target classification: ASCII only, a dot-atom local part
/// without pattern characters, a dotted domain, and no leading `-`.
pub fn email_identity(value: &str) -> Result<String> {
    let bad = || invalid_subject("Enter a plain ASCII email address such as name@example.test.");
    if value.is_empty() || value.len() > 254 || !value.is_ascii() || value.starts_with('-') {
        return Err(bad());
    }
    let (local, domain) = value.rsplit_once('@').ok_or_else(bad)?;
    if local.is_empty()
        || local.len() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+/=?^_`|~-.".contains(c))
    {
        return Err(bad());
    }
    let domain = crate::targets::domain(domain).map_err(|_| bad())?;
    if !domain.contains('.') {
        return Err(bad());
    }
    Ok(format!("{local}@{domain}"))
}

/// Canonical Account identity `<platform>:<identifier>`. The platform key is a
/// normalized provider site key; the identifier is a validated handle (without
/// `@`) or email address.
pub fn account_identity(value: &str) -> Result<String> {
    let bad = || CoreError::new("InvalidData", "Invalid account identity.");
    let (platform, identifier) = value.split_once(':').ok_or_else(bad)?;
    if platform.is_empty()
        || platform.len() > MAX_KEY_BYTES
        || !platform
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
    {
        return Err(bad());
    }
    let identifier = if identifier.contains('@') {
        email_identity(identifier).map_err(|_| bad())?
    } else {
        username_identity(identifier)
            .map_err(|_| bad())?
            .trim_start_matches('@')
            .to_owned()
    };
    Ok(format!("{platform}:{identifier}"))
}

/// Normalize an upstream platform/site name into a stable lowercase key
/// (`X (Twitter)` → `x_twitter`). Returns `None` when nothing usable remains.
pub fn platform_key(name: &str) -> Option<String> {
    let mut key = String::new();
    let mut pending_sep = false;
    for c in name.chars().flat_map(char::to_lowercase) {
        if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' {
            if pending_sep && !key.is_empty() {
                key.push('_');
            }
            pending_sep = false;
            key.push(c);
        } else {
            pending_sep = true;
        }
        if key.len() >= MAX_KEY_BYTES {
            break;
        }
    }
    let key = key.trim_matches(['.', '_']).to_owned();
    (!key.is_empty()).then_some(key)
}

/// Strip control and bidirectional/zero-width formatting characters from an
/// untrusted string and bound it to `max` bytes on a char boundary.
pub fn clean_text(value: &str, max: usize) -> String {
    let mut out = String::new();
    for c in value.chars() {
        if c.is_control()
            || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
        {
            continue;
        }
        if out.len() + c.len_utf8() > max {
            break;
        }
        out.push(c);
    }
    out.trim().to_owned()
}

/// Validate an untrusted URL: plain HTTP(S), a host, no credentials, bounded length.
pub fn safe_url(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > MAX_URL_BYTES || value.chars().any(char::is_control) {
        return None;
    }
    let url = crate::targets::web_url(value.trim()).ok()?;
    (url.len() <= MAX_URL_BYTES).then_some(url)
}

/// Provider-neutral outcome of one platform check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CheckStatus {
    /// The provider reported the identifier present/registered on the platform.
    Positive,
    /// The provider reported the identifier absent/not registered.
    Negative,
    /// The check was not performed by policy (e.g. a module that notifies the
    /// subject was skipped).
    Blocked,
    /// The provider attempted the check and it failed (network, rate limit, parse).
    Error,
    /// The provider returned a status MACSPLOIT does not recognize.
    Unknown,
}

/// One normalized platform check from an OSINT provider.
#[derive(Debug, Clone)]
pub struct OsintCheck {
    pub platform: String,
    pub platform_key: String,
    pub category: Option<String>,
    pub status: CheckStatus,
    pub upstream_status: String,
    pub url: Option<String>,
    /// True when the provider supplied a URL that failed validation (dropped).
    pub url_rejected: bool,
    pub reason: Option<String>,
    /// Bounded public profile fields (string/number/bool values only).
    pub profile: Map<String, Value>,
    /// Bounded, validated media URLs (e.g. avatar).
    pub media: Map<String, Value>,
    /// Upstream confidence label, when the provider supplies one.
    pub upstream_confidence: Option<String>,
}

/// Bound an untrusted metadata map: at most [`MAX_METADATA_KEYS`] keys, cleaned keys,
/// scalar values only (strings cleaned and bounded). Nested values are dropped.
pub fn bounded_profile(raw: &Map<String, Value>) -> Map<String, Value> {
    let mut out = Map::new();
    for (key, value) in raw {
        if out.len() >= MAX_METADATA_KEYS {
            break;
        }
        let key = clean_text(key, MAX_KEY_BYTES);
        if key.is_empty() {
            continue;
        }
        let value = match value {
            Value::String(text) => {
                let text = clean_text(text, MAX_FIELD_BYTES);
                if text.is_empty() {
                    continue;
                }
                Value::String(text)
            }
            Value::Bool(_) => value.clone(),
            Value::Number(n) if n.is_i64() || n.is_u64() => value.clone(),
            _ => continue,
        };
        out.insert(key, value);
    }
    out
}

/// Bound an untrusted media map: validated HTTP(S) URLs only.
pub fn bounded_media(raw: &Map<String, Value>) -> Map<String, Value> {
    let mut out = Map::new();
    for (key, value) in raw {
        if out.len() >= MAX_METADATA_KEYS {
            break;
        }
        let key = clean_text(key, MAX_KEY_BYTES);
        let Some(url) = value.as_str().and_then(safe_url) else {
            continue;
        };
        if !key.is_empty() {
            out.insert(key, Value::String(url));
        }
    }
    out
}

/// Counters for records that never became checks.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ParseStats {
    /// Records past [`MAX_RECORDS`].
    pub dropped_over_limit: usize,
    /// Records that were not objects or lacked a usable platform/status.
    pub malformed: usize,
    /// Records whose identifier did not match the scanned subject.
    pub mismatched_subject: usize,
}

/// Map normalized checks into the shared OSINT graph and a run summary.
///
/// * The subject asset is always emitted first and carries the per-run summary
///   (counts by status, bounded error/blocked/unknown lists, bounds/drops, and the
///   identity note) on its observation.
/// * Each positive check (deduplicated by platform within the run, capped at
///   [`MAX_POSITIVE`]) becomes an `Account` (`has_account` from the subject) with
///   `REPORTED` confidence and per-run observation metadata; a validated profile URL
///   becomes a `URL` asset (`profile_url` from the account).
/// * Negative checks are counted (the complete list stays in evidence).
///
/// `partial` is true when any check errored or returned an unknown status, or any
/// record was dropped, malformed, mismatched, or over a bound.
pub fn build_output(
    provider_id: &str,
    subject: &Subject,
    checks: Vec<OsintCheck>,
    stats: ParseStats,
) -> ParsedOutput {
    let mut counts: BTreeMap<CheckStatus, usize> = BTreeMap::new();
    let mut listed: BTreeMap<CheckStatus, Vec<Value>> = BTreeMap::new();
    let mut seen_platforms = HashSet::new();
    let mut accounts = Vec::new();
    let mut duplicates = 0usize;
    let mut positive_over_limit = 0usize;
    let mut urls_rejected = 0usize;

    for check in checks {
        *counts.entry(check.status).or_insert(0) += 1;
        if check.url_rejected {
            urls_rejected += 1;
        }
        match check.status {
            CheckStatus::Positive => {
                if !seen_platforms.insert(check.platform_key.clone()) {
                    duplicates += 1;
                    continue;
                }
                if accounts.len() >= MAX_POSITIVE {
                    positive_over_limit += 1;
                    continue;
                }
                accounts.push(check);
            }
            CheckStatus::Negative => {}
            status => {
                let list = listed.entry(status).or_default();
                if list.len() < MAX_SUMMARY_LIST {
                    list.push(json!({
                        "platform": check.platform,
                        "category": check.category,
                        "upstream_status": check.upstream_status,
                        "reason": check.reason,
                    }));
                }
            }
        }
    }

    let count = |status| counts.get(&status).copied().unwrap_or(0);
    let partial = count(CheckStatus::Error) > 0
        || count(CheckStatus::Unknown) > 0
        || stats.dropped_over_limit > 0
        || stats.malformed > 0
        || stats.mismatched_subject > 0
        || positive_over_limit > 0;
    let summary = json!({
        "kind": "osint_run_summary",
        "provider": provider_id,
        "subject": subject.canonical,
        "subject_kind": subject.kind,
        "checked": counts.values().sum::<usize>(),
        "counts": {
            "positive": count(CheckStatus::Positive),
            "negative": count(CheckStatus::Negative),
            "blocked": count(CheckStatus::Blocked),
            "error": count(CheckStatus::Error),
            "unknown": count(CheckStatus::Unknown),
        },
        "accounts": accounts.len(),
        "duplicates": duplicates,
        "positive_over_limit": positive_over_limit,
        "urls_rejected": urls_rejected,
        "records_dropped_over_limit": stats.dropped_over_limit,
        "records_malformed": stats.malformed,
        "records_mismatched_subject": stats.mismatched_subject,
        "errors": listed.remove(&CheckStatus::Error).unwrap_or_default(),
        "blocked": listed.remove(&CheckStatus::Blocked).unwrap_or_default(),
        "unknown": listed.remove(&CheckStatus::Unknown).unwrap_or_default(),
        "partial": partial,
        "identity_note": IDENTITY_NOTE,
    });

    let mut discoveries = vec![Discovery {
        asset_type: subject.asset_type(),
        value: subject.canonical.clone(),
        source: None,
        relationship: None,
        observation: Some(ObservationDetail {
            confidence: "CONFIRMED".into(),
            metadata: summary.clone(),
        }),
        metadata: json!({"source": "Analyst", "osint_subject": true}),
    }];
    for check in accounts {
        let identity = format!("{}:{}", check.platform_key, subject.query);
        let mut observation = json!({
            "kind": "osint_account",
            "provider": provider_id,
            "subject": subject.canonical,
            "subject_kind": subject.kind,
            "platform": check.platform,
            "platform_key": check.platform_key,
            "category": check.category,
            "status": check.status,
            "upstream_status": check.upstream_status,
            "url": check.url,
            "reason": check.reason,
            "profile": Value::Object(check.profile),
            "media": Value::Object(check.media),
            "identity_note": IDENTITY_NOTE,
        });
        if let Some(confidence) = &check.upstream_confidence {
            observation["upstream_confidence"] = json!(confidence);
        }
        discoveries.push(Discovery {
            asset_type: AssetType::Account,
            value: identity.clone(),
            source: Some(subject.canonical.clone()),
            relationship: Some(RelationshipType::HasAccount),
            observation: Some(ObservationDetail {
                confidence: CONFIDENCE_REPORTED.into(),
                metadata: observation.clone(),
            }),
            metadata: json!({
                "tool": provider_id,
                "platform": check.platform,
                "platform_key": check.platform_key,
                "category": check.category,
                "identifier": subject.query,
                "subject_kind": subject.kind,
            }),
        });
        if let Some(url) = check.url {
            discoveries.push(Discovery {
                asset_type: AssetType::URL,
                value: url,
                source: Some(identity),
                relationship: Some(RelationshipType::ProfileUrl),
                observation: Some(ObservationDetail {
                    confidence: CONFIDENCE_REPORTED.into(),
                    metadata: json!({
                        "kind": "osint_profile_url",
                        "provider": provider_id,
                        "platform": check.platform,
                        "subject": subject.canonical,
                    }),
                }),
                metadata: json!({"tool": provider_id, "osint_profile": true}),
            });
        }
    }
    ParsedOutput {
        discoveries,
        partial,
        summary: Some(summary),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_identity_is_strict() {
        assert_eq!(
            username_identity("@doctor.doom_1").unwrap(),
            "@doctor.doom_1"
        );
        assert_eq!(username_identity("handle").unwrap(), "@handle");
        for bad in [
            "",
            "@",
            "-rf",
            "@-x",
            ".hidden",
            "a b",
            "a[0-9]",
            "a\\b",
            "a{2}",
            "ü",
            "a;b",
            "$(id)",
            &"a".repeat(65),
        ] {
            assert!(username_identity(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn email_identity_is_strict() {
        assert_eq!(
            email_identity("Person.Name@EXAMPLE.test").unwrap(),
            "Person.Name@example.test"
        );
        for bad in [
            "-x@example.test",
            "a@localhost",
            "a[1]@example.test",
            "a\\b@example.test",
            "a..b@example.test",
            "ü@example.test",
            "a@b@example.test",
            "@example.test",
            "a@",
        ] {
            assert!(email_identity(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn account_identity_and_platform_keys() {
        assert_eq!(platform_key("X (Twitter)").as_deref(), Some("x_twitter"));
        assert_eq!(platform_key("Made.porn").as_deref(), Some("made.porn"));
        assert_eq!(platform_key(" \u{202E}!! "), None);
        assert_eq!(
            account_identity("github:octo").unwrap(),
            "github:octo".to_owned()
        );
        assert_eq!(
            account_identity("amazon:a@EXAMPLE.test").unwrap(),
            "amazon:a@example.test"
        );
        assert!(account_identity("GitHub:octo").is_err());
        assert!(account_identity("github:-x").is_err());
        assert!(account_identity("nocolon").is_err());
    }

    #[test]
    fn clean_text_strips_controls_and_bounds() {
        assert_eq!(clean_text("a\u{1b}[31mb\u{202E}c\n", 64), "a[31mbc");
        assert_eq!(clean_text("ééé", 3), "é");
    }

    #[test]
    fn safe_url_rejects_non_http_and_credentials() {
        assert!(safe_url("https://example.test/u").is_some());
        let credential_url = ["https://", "user:pw", "@example.test/"].concat();
        for bad in [
            "javascript:alert(1)",
            "file:///etc/passwd",
            credential_url.as_str(),
            "not a url",
            "",
        ] {
            assert!(safe_url(bad).is_none(), "accepted {bad:?}");
        }
        assert!(safe_url(&format!("https://example.test/{}", "a".repeat(3000))).is_none());
    }

    #[test]
    fn subject_requires_username_or_email_target() {
        let s = Subject::from_target(TargetType::Username, "@octo").unwrap();
        assert_eq!((s.kind, s.query.as_str()), (SubjectKind::Username, "octo"));
        assert!(Subject::from_target(TargetType::Domain, "example.test").is_err());
    }
}
