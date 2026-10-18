//! Deterministic Finding drafts (Issue #79 + Level 1 of #81, parent #68).
//!
//! The analyst should never have to create a blank Finding and then retype facts
//! MACSPLOIT already holds. When an analyst chooses "Create Finding" from a result, an
//! asset, a selection of results, or a whole run, the core builds the best **safe**
//! draft it can from durable normalized state and returns it; the structured editor then
//! opens already populated. Pressing **Create** persists it through the ordinary
//! transactional [`crate::findings::Store::create_finding`] path — a draft is never
//! inserted on its own.
//!
//! Invariants this module upholds:
//!
//! * **A draft is not a Finding.** [`FindingDraft`] is a typed, non-persisted read model.
//!   Drafting is strictly read-only (it opens the workspace store read-only) and writes
//!   nothing.
//! * **Provider output is not the draft.** Drafts are built from durable
//!   Asset/Observation/Evidence/run records, never from console text or raw stdout.
//! * **MACSPLOIT never invents a vulnerability.** A generic reconnaissance/OSINT
//!   observation is drafted as a *factual, informational* note: severity INFORMATIONAL,
//!   the safest confidence, empty remediation, and no CVE/CWE unless a reviewed rule
//!   genuinely supplied one. Only a [`ReviewedFindingHint`] — which has no wire path and
//!   can only originate from trusted in-core rule metadata (TLS/Nuclei/native rules,
//!   #83–#85, not implemented here) — may propose richer severity/text/identifiers.
//! * **Swift is never the authority.** Every referenced observation/asset/evidence id is
//!   validated against the workspace (and, when run-scoped, the run) by the core;
//!   cross-workspace and wrong-run references are rejected.

use crate::{
    assets::Id,
    database::Store,
    error::{CoreError, Result},
    findings::{
        FindingConfidence, FindingStatus, Severity, MAX_AFFECTED_ASSETS, MAX_EVIDENCE_LINKS,
        MAX_TEXT_BYTES, MAX_TITLE_BYTES,
    },
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};

/// Most durable results a single draft may be built from (a whole run can be far larger;
/// the analyst narrows the selection instead of drafting an unbounded wall of text).
pub const MAX_DRAFT_OBSERVATIONS: usize = 200;
/// Most individual facts enumerated in a generated description (the rest are summarized
/// as a bounded "+N more" so the draft text stays reviewable).
pub const MAX_DRAFT_FACTS: usize = 20;

/// How a draft was derived — surfaced so the UI/analyst can see whether the values came
/// from a reviewed rule or from a safe generic observation summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DraftKind {
    /// Built from reviewed scanner/rule metadata (future; see [`ReviewedFindingHint`]).
    ReviewedRule,
    /// Built from generic normalized observations — factual and informational only.
    GenericObservation,
}

/// A typed selection of durable context to draft a Finding from. Every id is validated by
/// the core; Swift is never trusted to enforce workspace or run isolation.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DraftContext {
    /// The run (a `chain_runs` row, as the UI's run picker lists it). When set, every
    /// selected observation must belong to this run; it also names the run in draft text.
    #[serde(default)]
    pub run_id: Option<Id>,
    /// Selected result rows, by durable observation id.
    #[serde(default)]
    pub observation_ids: Vec<Id>,
    /// Explicitly selected affected assets (in addition to those an observation implies).
    #[serde(default)]
    pub asset_ids: Vec<Id>,
    /// Explicitly selected supporting evidence (in addition to observation evidence).
    #[serde(default)]
    pub evidence_ids: Vec<Id>,
    /// The analyst's chosen primary affected asset (must be among the affected set).
    #[serde(default)]
    pub primary_asset_id: Option<Id>,
}

/// One affected asset in a draft, carrying its identity so the editor can show it without
/// another round trip.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DraftAsset {
    pub asset_id: Id,
    pub asset_type: String,
    pub asset_identity: String,
    pub is_primary: bool,
}

/// One evidence reference in a draft, with a bounded display label (never the body).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DraftEvidence {
    pub evidence_id: Id,
    pub label: String,
}

/// A typed, non-persisted Finding draft. Carries everything the structured editor needs
/// to open already populated. The analyst may change any field before pressing Create.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FindingDraft {
    pub kind: DraftKind,
    pub title: String,
    pub severity: Severity,
    pub confidence: FindingConfidence,
    pub suggested_status: FindingStatus,
    pub description: String,
    pub reproduction: String,
    pub remediation: String,
    pub tags: Vec<String>,
    pub cwe_ids: Vec<String>,
    pub cve_ids: Vec<String>,
    pub primary_asset_id: Option<Id>,
    pub affected_assets: Vec<DraftAsset>,
    pub evidence: Vec<DraftEvidence>,
    /// Immutable source attribution, set only when all selected results share one provider
    /// run (so it matches [`crate::findings`]'s provider/run validation).
    pub source_provider: Option<String>,
    pub source_run_id: Option<Id>,
    /// Human-readable notes on how the draft was derived (shown as assistive context).
    pub provenance: Vec<String>,
}

impl FindingDraft {
    /// The `NewFinding` an *unedited* draft would create — the canonical "Create from this
    /// draft" mapping. The analyst normally edits the draft first; the Swift editor builds
    /// its own `NewFinding` from the (possibly changed) fields, mirroring this mapping.
    /// Create always runs through the ordinary transactional create path.
    pub fn to_new_finding(&self) -> crate::findings::NewFinding {
        crate::findings::NewFinding {
            title: self.title.clone(),
            severity: self.severity,
            confidence: self.confidence,
            status: Some(self.suggested_status),
            description: self.description.clone(),
            reproduction: self.reproduction.clone(),
            remediation: self.remediation.clone(),
            tags: self.tags.clone(),
            cwe_ids: self.cwe_ids.clone(),
            cve_ids: self.cve_ids.clone(),
            primary_asset_id: self.primary_asset_id,
            additional_asset_ids: self
                .affected_assets
                .iter()
                .filter(|a| !a.is_primary)
                .map(|a| a.asset_id)
                .collect(),
            evidence_ids: self.evidence.iter().map(|e| e.evidence_id).collect(),
            source_provider: self.source_provider.clone(),
            source_run_id: self.source_run_id,
        }
    }
}

/// Structured draft semantics a **reviewed** scanner rule may attach to a result in the
/// future (TLS/Nuclei/native observation rules, #83–#85). No provider emits this yet and
/// there is deliberately **no wire path** to set it, so a hint can only ever originate
/// from trusted in-core rule metadata — never from arbitrary provider text. The draft
/// builder already consumes it so richer drafts will not need a second pipeline.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReviewedFindingHint {
    pub title: Option<String>,
    pub severity: Option<Severity>,
    pub confidence: Option<FindingConfidence>,
    pub status: Option<FindingStatus>,
    pub description: Option<String>,
    pub reproduction: Option<String>,
    pub remediation: Option<String>,
    pub tags: Vec<String>,
    pub cwe_ids: Vec<String>,
    pub cve_ids: Vec<String>,
}

/// One durable observation resolved for drafting (the fields the pure builder reads).
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedObservation {
    pub observation_id: Id,
    pub asset_id: Id,
    pub asset_type: String,
    pub asset_identity: String,
    pub provider_id: Option<String>,
    pub discovered_by: String,
    pub provider_run_id: Option<Id>,
    pub evidence_id: Option<Id>,
    pub observed_value: String,
}

/// The validated, workspace-scoped context the pure builder turns into a [`FindingDraft`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ResolvedSelection {
    /// The run (chain) the selection came from, for draft text; not the source attribution.
    pub chain_name: Option<String>,
    pub observations: Vec<ResolvedObservation>,
    /// Explicitly selected assets not necessarily tied to a selected observation.
    pub extra_assets: Vec<DraftAsset>,
    /// Explicitly selected evidence not necessarily tied to a selected observation.
    pub extra_evidence: Vec<DraftEvidence>,
    pub requested_primary: Option<Id>,
    /// Set only when all observations share one provider run: (provider_run_id, provider).
    pub source_run: Option<(Id, String)>,
}

/// Strip control chars, collapse to a trimmed string, and truncate to `max` bytes on a
/// char boundary (generated text is clamped, never rejected).
fn clamp(value: &str, max: usize) -> String {
    let cleaned: String = value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    if cleaned.len() <= max {
        return cleaned;
    }
    let mut end = max;
    while end > 0 && !cleaned.is_char_boundary(end) {
        end -= 1;
    }
    cleaned[..end].trim_end().to_owned()
}

/// A short, provider-or-discovery label for draft text.
fn provider_label(obs: &ResolvedObservation) -> String {
    obs.provider_id
        .clone()
        .unwrap_or_else(|| obs.discovered_by.clone())
}

/// Build a deterministic draft from a validated selection. Pure (no I/O): the same inputs
/// always produce the same draft, independent of any console text or app restart. A
/// `hint` is only ever supplied from trusted in-core rule metadata.
pub fn build_draft(
    selection: &ResolvedSelection,
    hint: Option<&ReviewedFindingHint>,
) -> FindingDraft {
    // Affected assets: those implied by the selected observations, then any explicitly
    // chosen assets, de-duplicated by asset id (first identity wins).
    let mut affected: Vec<DraftAsset> = Vec::new();
    let mut push_asset = |asset_id: Id, asset_type: &str, identity: &str| {
        if !affected.iter().any(|a| a.asset_id == asset_id) {
            affected.push(DraftAsset {
                asset_id,
                asset_type: clamp(asset_type, MAX_TITLE_BYTES),
                asset_identity: clamp(identity, MAX_TEXT_BYTES),
                is_primary: false,
            });
        }
    };
    for obs in &selection.observations {
        push_asset(obs.asset_id, &obs.asset_type, &obs.asset_identity);
    }
    for asset in &selection.extra_assets {
        push_asset(asset.asset_id, &asset.asset_type, &asset.asset_identity);
    }
    affected.truncate(MAX_AFFECTED_ASSETS);

    // Primary: the analyst's choice when present and still in the set; else the first
    // affected asset (deterministic — observations, then extra assets, in selection order).
    let primary_id = selection
        .requested_primary
        .filter(|id| affected.iter().any(|a| a.asset_id == *id))
        .or_else(|| affected.first().map(|a| a.asset_id));
    for asset in &mut affected {
        asset.is_primary = Some(asset.asset_id) == primary_id;
    }

    // Evidence: observation evidence first (labelled from the observation), then any
    // explicitly selected evidence, de-duplicated by id.
    let mut evidence: Vec<DraftEvidence> = Vec::new();
    let mut push_evidence = |evidence_id: Id, label: String| {
        if !evidence.iter().any(|e| e.evidence_id == evidence_id) {
            evidence.push(DraftEvidence {
                evidence_id,
                label: clamp(&label, MAX_TITLE_BYTES),
            });
        }
    };
    for obs in &selection.observations {
        if let Some(evidence_id) = obs.evidence_id {
            push_evidence(
                evidence_id,
                format!("{} · {}", provider_label(obs), obs.asset_identity),
            );
        }
    }
    for item in &selection.extra_evidence {
        push_evidence(item.evidence_id, item.label.clone());
    }
    evidence.truncate(MAX_EVIDENCE_LINKS);

    let (source_run_id, source_provider) = match &selection.source_run {
        Some((run, provider)) => (Some(*run), Some(clamp(provider, 128))),
        None => (None, None),
    };

    // A reviewed rule, when present, provides the security semantics; a generic draft
    // stays strictly factual and informational and invents nothing.
    let generic = generic_fields(selection, &affected);
    let kind = if hint.is_some() {
        DraftKind::ReviewedRule
    } else {
        DraftKind::GenericObservation
    };

    let title = hint
        .and_then(|h| h.title.clone())
        .map(|t| clamp(&t, MAX_TITLE_BYTES))
        .filter(|t| !t.is_empty())
        .unwrap_or(generic.title);
    let severity = hint
        .and_then(|h| h.severity)
        .unwrap_or(Severity::Informational);
    let confidence = hint
        .and_then(|h| h.confidence)
        .unwrap_or(FindingConfidence::Low);
    let suggested_status = hint
        .and_then(|h| h.status)
        .filter(|s| s.is_valid_initial())
        .unwrap_or(FindingStatus::Draft);
    let description = hint
        .and_then(|h| h.description.clone())
        .map(|t| clamp(&t, MAX_TEXT_BYTES))
        .filter(|t| !t.is_empty())
        .unwrap_or(generic.description);
    let reproduction = hint
        .and_then(|h| h.reproduction.clone())
        .map(|t| clamp(&t, MAX_TEXT_BYTES))
        .filter(|t| !t.is_empty())
        .unwrap_or(generic.reproduction);
    // Remediation is EMPTY for generic observations — MACSPLOIT does not tell an analyst
    // to "fix" an ordinary reconnaissance fact. Only a reviewed rule supplies one.
    let remediation = hint
        .and_then(|h| h.remediation.clone())
        .map(|t| clamp(&t, MAX_TEXT_BYTES))
        .unwrap_or_default();
    // Identifiers are NEVER inferred from arbitrary text — only a reviewed rule's trusted
    // metadata can carry them. Shape is validated later by create_finding.
    let (tags, cwe_ids, cve_ids) = match hint {
        Some(h) => (h.tags.clone(), h.cwe_ids.clone(), h.cve_ids.clone()),
        None => (Vec::new(), Vec::new(), Vec::new()),
    };

    let mut provenance = Vec::new();
    match kind {
        DraftKind::GenericObservation => provenance.push(
            "Factual informational draft from normalized observations — severity, remediation, and identifiers were not inferred.".to_string(),
        ),
        DraftKind::ReviewedRule => provenance
            .push("Draft populated from reviewed rule metadata.".to_string()),
    }
    if let Some(name) = &selection.chain_name {
        provenance.push(clamp(&format!("Source run: {name}"), MAX_TITLE_BYTES));
    }

    FindingDraft {
        kind,
        title,
        severity,
        confidence,
        suggested_status,
        description,
        reproduction,
        remediation,
        tags,
        cwe_ids,
        cve_ids,
        primary_asset_id: primary_id,
        affected_assets: affected,
        evidence,
        source_provider,
        source_run_id,
        provenance,
    }
}

struct GenericFields {
    title: String,
    description: String,
    reproduction: String,
}

/// Factual, non-accusatory draft text for generic observations. Never claims a
/// vulnerability, exposure, compromise, or remediation.
fn generic_fields(selection: &ResolvedSelection, affected: &[DraftAsset]) -> GenericFields {
    let source = selection
        .chain_name
        .clone()
        .or_else(|| selection.observations.first().map(provider_label))
        .unwrap_or_else(|| "the workflow".to_string());

    match selection.observations.as_slice() {
        // A single observation: name the concrete fact that was observed.
        [obs] => {
            let provider = provider_label(obs);
            let title = clamp(
                &format!(
                    "{} ({}) observed via {}",
                    obs.asset_identity, obs.asset_type, provider
                ),
                MAX_TITLE_BYTES,
            );
            let chain_clause = selection
                .chain_name
                .as_ref()
                .map(|c| format!(" during {c}"))
                .unwrap_or_default();
            let description = clamp(
                &format!(
                    "{provider} reported {} {}{chain_clause}. This draft records the observation as a fact, not a security conclusion.",
                    obs.asset_type, obs.asset_identity
                ),
                MAX_TEXT_BYTES,
            );
            let reproduction = clamp(
                &format!(
                    "Re-run {source} against the authorized target and confirm {} {} is still observed.",
                    obs.asset_type, obs.asset_identity
                ),
                MAX_TEXT_BYTES,
            );
            GenericFields {
                title,
                description,
                reproduction,
            }
        }
        // No observations — drafting purely from explicitly selected asset(s).
        [] => {
            let subject = affected
                .iter()
                .find(|a| a.is_primary)
                .or_else(|| affected.first());
            let title = match subject {
                Some(a) => clamp(
                    &format!(
                        "{} ({}) selected for review",
                        a.asset_identity, a.asset_type
                    ),
                    MAX_TITLE_BYTES,
                ),
                None => "Finding".to_string(),
            };
            let description = match subject {
                Some(a) => clamp(
                    &format!(
                        "Draft for {} {}. Add the security conclusion this asset concerns.",
                        a.asset_type, a.asset_identity
                    ),
                    MAX_TEXT_BYTES,
                ),
                None => String::new(),
            };
            GenericFields {
                title,
                description,
                reproduction: String::new(),
            }
        }
        // Several observations: summarize a bounded number of facts.
        many => {
            let count = many.len();
            let title = match affected.iter().find(|a| a.is_primary) {
                Some(primary) if affected.len() == 1 => clamp(
                    &format!("{count} observations affecting {}", primary.asset_identity),
                    MAX_TITLE_BYTES,
                ),
                _ => clamp(
                    &format!("{count} observations from {source}"),
                    MAX_TITLE_BYTES,
                ),
            };
            let mut description = format!(
                "{count} normalized observations from {source} are referenced by this draft. It records observed facts, not a security conclusion:\n"
            );
            for obs in many.iter().take(MAX_DRAFT_FACTS) {
                description.push_str(&format!(
                    "- {}: {} {}\n",
                    provider_label(obs),
                    obs.asset_type,
                    obs.asset_identity
                ));
            }
            if count > MAX_DRAFT_FACTS {
                description.push_str(&format!("- (+{} more)\n", count - MAX_DRAFT_FACTS));
            }
            let reproduction = clamp(
                &format!("Re-run {source} against the authorized target and confirm the referenced results are still present."),
                MAX_TEXT_BYTES,
            );
            GenericFields {
                title,
                description: clamp(&description, MAX_TEXT_BYTES),
                reproduction,
            }
        }
    }
}

impl Store {
    /// Build a deterministic, read-only [`FindingDraft`] from a validated selection of
    /// durable context. Performs no network activity and inserts no Finding; the analyst
    /// persists it through [`crate::findings::Store::create_finding`].
    pub fn draft_finding(&self, workspace: Id, context: DraftContext) -> Result<FindingDraft> {
        // De-duplicate and bound the requested selection up front.
        let observation_ids = dedup(context.observation_ids);
        let asset_ids = dedup(context.asset_ids);
        let evidence_ids = dedup(context.evidence_ids);
        if observation_ids.len() > MAX_DRAFT_OBSERVATIONS {
            return Err(CoreError::new(
                "InvalidRequest",
                &format!("Select at most {MAX_DRAFT_OBSERVATIONS} results for one draft; narrow the selection."),
            ));
        }
        if asset_ids.len() > MAX_AFFECTED_ASSETS || evidence_ids.len() > MAX_EVIDENCE_LINKS {
            return Err(CoreError::new(
                "InvalidRequest",
                "The selected asset/evidence list exceeds its limit.",
            ));
        }
        if observation_ids.is_empty() && asset_ids.is_empty() {
            return Err(CoreError::new(
                "InvalidRequest",
                "Select at least one result or asset to draft a finding from.",
            ));
        }

        let conn = self.read_only(workspace)?;

        // If run-scoped, the run (a chain) must exist; its name is used in draft text and
        // every selected observation must belong to it.
        let chain_name: Option<String> = match context.run_id {
            Some(run) => Some(
                conn.query_row(
                    "SELECT name FROM chain_runs WHERE workspace_id=?1 AND id=?2",
                    params![workspace.to_string(), run.to_string()],
                    |r| r.get(0),
                )
                .optional()?
                .ok_or_else(|| {
                    CoreError::new(
                        "InvalidRequest",
                        "The selected run does not exist in this workspace.",
                    )
                })?,
            ),
            None => None,
        };

        let mut observations = Vec::with_capacity(observation_ids.len());
        for id in &observation_ids {
            observations.push(resolve_observation(&conn, workspace, context.run_id, *id)?);
        }
        let extra_assets = asset_ids
            .iter()
            .map(|id| resolve_asset(&conn, workspace, *id))
            .collect::<Result<Vec<_>>>()?;
        let extra_evidence = evidence_ids
            .iter()
            .map(|id| resolve_evidence(&conn, workspace, *id))
            .collect::<Result<Vec<_>>>()?;

        // The chosen primary must be one of the affected assets.
        if let Some(primary) = context.primary_asset_id {
            let known = observations.iter().any(|o| o.asset_id == primary)
                || extra_assets.iter().any(|a| a.asset_id == primary);
            if !known {
                return Err(CoreError::new(
                    "InvalidRequest",
                    "The chosen primary asset is not among the selected affected assets.",
                ));
            }
        }

        // Attribute the source run only when every selected observation shares a single
        // provider run — this keeps source_provider/source_run_id consistent with the
        // findings store's provider/run-match rule.
        let source_run = single_provider_run(&conn, workspace, &observations)?;

        let selection = ResolvedSelection {
            chain_name,
            observations,
            extra_assets,
            extra_evidence,
            requested_primary: context.primary_asset_id,
            source_run,
        };
        Ok(build_draft(&selection, None))
    }

    /// Open the workspace store read-only (drafting never writes or migrates).
    fn read_only(&self, workspace: Id) -> Result<Connection> {
        let directory = self.directory(workspace);
        let path = directory.join("workspace.sqlite");
        if !path.is_file() {
            return Err(CoreError::new(
                "WorkspaceNotFound",
                "Workspace does not exist.",
            ));
        }
        if directory.is_symlink() || path.is_symlink() {
            return Err(CoreError::new(
                "StorageError",
                "Workspace paths cannot be symbolic links.",
            ));
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if !(4..=8).contains(&version) {
            return Err(CoreError::new(
                "MigrationFailure",
                "Open this workspace with a compatible core before drafting findings.",
            ));
        }
        let workspace_exists: bool = connection
            .prepare("SELECT 1 FROM workspaces WHERE id=?1")?
            .exists([workspace.to_string()])?;
        if !workspace_exists {
            return Err(CoreError::new(
                "WorkspaceNotFound",
                "Workspace identity does not match its store.",
            ));
        }
        Ok(connection)
    }
}

fn dedup(ids: Vec<Id>) -> Vec<Id> {
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        if !out.contains(&id) {
            out.push(id);
        }
    }
    out
}

fn parse_id(s: String) -> rusqlite::Result<Id> {
    Id::parse_str(&s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}

/// Resolve one selected observation, enforcing workspace and (when set) run membership.
fn resolve_observation(
    conn: &Connection,
    workspace: Id,
    run: Option<Id>,
    observation: Id,
) -> Result<ResolvedObservation> {
    let resolved = conn
        .query_row(
            "SELECT o.id,o.asset_id,a.asset_type,a.canonical_identity,r.provider_id,
                    o.discovered_by,o.provider_run_id,o.evidence_id,o.observed_value
             FROM observations o
             JOIN assets a ON a.workspace_id=o.workspace_id AND a.id=o.asset_id
             LEFT JOIN provider_runs r ON r.workspace_id=o.workspace_id AND r.id=o.provider_run_id
             WHERE o.workspace_id=?1 AND o.id=?2
               AND (?3 IS NULL OR o.provider_run_id IN
                    (SELECT id FROM provider_runs WHERE workspace_id=?1 AND chain_id=?3))",
            params![
                workspace.to_string(),
                observation.to_string(),
                run.map(|r| r.to_string())
            ],
            |row| {
                Ok(ResolvedObservation {
                    observation_id: parse_id(row.get(0)?)?,
                    asset_id: parse_id(row.get(1)?)?,
                    asset_type: row.get(2)?,
                    asset_identity: row.get(3)?,
                    provider_id: row.get(4)?,
                    discovered_by: row.get(5)?,
                    provider_run_id: row.get::<_, Option<String>>(6)?.map(parse_id).transpose()?,
                    evidence_id: row.get::<_, Option<String>>(7)?.map(parse_id).transpose()?,
                    observed_value: row.get(8)?,
                })
            },
        )
        .optional()?;
    resolved.ok_or_else(|| {
        CoreError::new(
            "InvalidRequest",
            "A selected result is not part of this workspace or run.",
        )
    })
}

fn resolve_asset(conn: &Connection, workspace: Id, asset: Id) -> Result<DraftAsset> {
    conn.query_row(
        "SELECT asset_type,canonical_identity FROM assets WHERE workspace_id=?1 AND id=?2",
        params![workspace.to_string(), asset.to_string()],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    )
    .optional()?
    .map(|(asset_type, asset_identity)| DraftAsset {
        asset_id: asset,
        asset_type,
        asset_identity,
        is_primary: false,
    })
    .ok_or_else(|| {
        CoreError::new(
            "AssetNotFound",
            "A selected asset does not exist in this workspace.",
        )
    })
}

fn resolve_evidence(conn: &Connection, workspace: Id, evidence: Id) -> Result<DraftEvidence> {
    conn.query_row(
        "SELECT provider,target FROM evidence WHERE workspace_id=?1 AND id=?2",
        params![workspace.to_string(), evidence.to_string()],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    )
    .optional()?
    .map(|(provider, target)| DraftEvidence {
        evidence_id: evidence,
        label: format!("{provider} · {target}"),
    })
    .ok_or_else(|| {
        CoreError::new(
            "InvalidRequest",
            "A selected evidence record does not exist in this workspace.",
        )
    })
}

/// When all selected observations share exactly one provider run, return that run id and
/// its provider for immutable source attribution; otherwise `None`.
fn single_provider_run(
    conn: &Connection,
    workspace: Id,
    observations: &[ResolvedObservation],
) -> Result<Option<(Id, String)>> {
    let mut runs: Vec<Id> = Vec::new();
    for obs in observations {
        if let Some(run) = obs.provider_run_id {
            if !runs.contains(&run) {
                runs.push(run);
            }
        } else {
            return Ok(None);
        }
    }
    match runs.as_slice() {
        [run] => {
            let provider: Option<String> = conn
                .query_row(
                    "SELECT provider_id FROM provider_runs WHERE workspace_id=?1 AND id=?2",
                    params![workspace.to_string(), run.to_string()],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(provider.map(|p| (*run, p)))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(
        id: &str,
        asset: &str,
        identity: &str,
        provider: &str,
        run: Option<Id>,
        evidence: Option<Id>,
    ) -> ResolvedObservation {
        ResolvedObservation {
            observation_id: Id::new_v4(),
            asset_id: Id::parse_str(asset).unwrap_or_else(|_| Id::new_v4()),
            asset_type: id.to_string(),
            asset_identity: identity.to_string(),
            provider_id: Some(provider.to_string()),
            discovered_by: provider.to_string(),
            provider_run_id: run,
            evidence_id: evidence,
            observed_value: identity.to_string(),
        }
    }

    #[test]
    fn single_generic_observation_is_factual_and_informational() {
        let asset = Id::new_v4();
        let selection = ResolvedSelection {
            chain_name: Some("Direct IP Recon".into()),
            observations: vec![ResolvedObservation {
                asset_id: asset,
                asset_type: "Service".into(),
                asset_identity: "tcp/443 on 192.0.2.10".into(),
                ..obs(
                    "Service",
                    &asset.to_string(),
                    "tcp/443 on 192.0.2.10",
                    "nmap",
                    None,
                    None,
                )
            }],
            ..Default::default()
        };
        let draft = build_draft(&selection, None);
        assert_eq!(draft.kind, DraftKind::GenericObservation);
        assert_eq!(draft.severity, Severity::Informational);
        assert_eq!(draft.confidence, FindingConfidence::Low);
        assert_eq!(draft.suggested_status, FindingStatus::Draft);
        assert!(draft.remediation.is_empty(), "no remediation invented");
        assert!(draft.cve_ids.is_empty() && draft.cwe_ids.is_empty());
        assert!(draft.title.contains("tcp/443 on 192.0.2.10"));
        assert!(draft.title.contains("observed"));
        let lower = format!("{} {}", draft.title, draft.description).to_lowercase();
        for word in ["vulnerab", "exploit", "exposed", "insecure", "close this"] {
            assert!(
                !lower.contains(word),
                "generic draft must not accuse: {word}"
            );
        }
        assert_eq!(draft.primary_asset_id, Some(asset));
        assert!(draft
            .affected_assets
            .iter()
            .all(|a| a.is_primary == (a.asset_id == asset)));
        assert!(draft.reproduction.to_lowercase().contains("re-run"));
    }

    #[test]
    fn reviewed_rule_hint_populates_without_a_scanner() {
        let asset = Id::new_v4();
        let selection = ResolvedSelection {
            observations: vec![obs(
                "Service",
                &asset.to_string(),
                "api.example.com:443",
                "tls",
                None,
                None,
            )],
            ..Default::default()
        };
        let hint = ReviewedFindingHint {
            title: Some("Expired TLS certificate".into()),
            severity: Some(Severity::Medium),
            confidence: Some(FindingConfidence::High),
            status: Some(FindingStatus::Open),
            description: Some("The certificate presented by the service is expired.".into()),
            reproduction: Some("Connect and inspect the certificate validity dates.".into()),
            remediation: Some("Reissue and deploy a current certificate.".into()),
            cwe_ids: vec!["CWE-295".into()],
            ..Default::default()
        };
        let draft = build_draft(&selection, Some(&hint));
        assert_eq!(draft.kind, DraftKind::ReviewedRule);
        assert_eq!(draft.title, "Expired TLS certificate");
        assert_eq!(draft.severity, Severity::Medium);
        assert_eq!(draft.confidence, FindingConfidence::High);
        assert_eq!(draft.suggested_status, FindingStatus::Open);
        assert_eq!(
            draft.remediation,
            "Reissue and deploy a current certificate."
        );
        assert_eq!(draft.cwe_ids, vec!["CWE-295".to_string()]);
    }

    #[test]
    fn multiple_observations_dedupe_assets_and_bound_facts() {
        let a1 = Id::new_v4();
        let a2 = Id::new_v4();
        let mut observations = Vec::new();
        for i in 0..(MAX_DRAFT_FACTS + 5) {
            let asset = if i % 2 == 0 { a1 } else { a2 };
            observations.push(obs(
                "Website",
                &asset.to_string(),
                &format!("https://h{i}.example.test/"),
                "httpx",
                None,
                None,
            ));
        }
        let selection = ResolvedSelection {
            chain_name: Some("Domain Recon".into()),
            observations,
            requested_primary: Some(a2),
            ..Default::default()
        };
        let draft = build_draft(&selection, None);
        // Two distinct assets regardless of how many observations referenced them.
        assert_eq!(draft.affected_assets.len(), 2);
        assert_eq!(draft.primary_asset_id, Some(a2));
        assert_eq!(
            draft
                .affected_assets
                .iter()
                .filter(|a| a.is_primary)
                .count(),
            1
        );
        // Enumerated facts are bounded with a summarizing remainder line.
        assert!(draft.description.contains("+5 more"));
        assert!(draft.description.len() <= MAX_TEXT_BYTES);
    }

    #[test]
    fn requested_primary_outside_the_set_falls_back_deterministically() {
        let asset = Id::new_v4();
        let selection = ResolvedSelection {
            observations: vec![obs(
                "Host",
                &asset.to_string(),
                "example.test",
                "native_dns",
                None,
                None,
            )],
            requested_primary: Some(Id::new_v4()), // not in the set
            ..Default::default()
        };
        let draft = build_draft(&selection, None);
        assert_eq!(draft.primary_asset_id, Some(asset));
    }

    #[test]
    fn clamp_strips_control_chars_and_bounds_length() {
        assert_eq!(clamp("  a\u{0}b  ", 200), "a b");
        assert_eq!(
            clamp(&"a".repeat(300), MAX_TITLE_BYTES).len(),
            MAX_TITLE_BYTES
        );
    }
}
