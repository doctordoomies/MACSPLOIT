use crate::{
    assets::Id,
    error::{CoreError, Result},
    orchestration::Engine,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const VERSION: u32 = 1;
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Deserialize)]
pub struct Request {
    pub protocol_version: u32,
    pub request_id: String,
    #[serde(flatten)]
    pub command: Command,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Command {
    Hello {},
    ListWorkspaces {},
    CreateWorkspace {
        name: String,
        scope: Vec<String>,
    },
    UpdateWorkspaceScope {
        workspace_id: Id,
        scope: Vec<String>,
    },
    AddTarget {
        workspace_id: Id,
        value: String,
    },
    Snapshot {
        workspace_id: Id,
    },
    /// Read-only durable reconstruction of one chain's provider observations,
    /// relationship provenance, and evidence metadata.
    ChainResults {
        workspace_id: Id,
        chain_id: Id,
    },
    EventsAfter {
        workspace_id: Id,
        after: i64,
    },
    StartChain {
        workspace_id: Id,
        target_id: Id,
        #[serde(default)]
        chain: crate::orchestration::ChainKind,
        /// Optional per-run options (e.g. `{"wordlist_path": "..."}` for content
        /// discovery). Defaults to an empty object.
        #[serde(default)]
        options: serde_json::Value,
    },
    CancelChain {
        workspace_id: Id,
        chain_id: Id,
    },
    ReadEvidence {
        workspace_id: Id,
        evidence_id: Id,
    },
    ListProviders {},
    /// Read-only: is the target covered by workspace scope, and what exact entry would
    /// authorize it. No scope mutation, no network activity.
    TargetScopeStatus {
        workspace_id: Id,
        target_id: Id,
    },
    /// Add only the narrowest exact scope entry needed to authorize the target (no-op if
    /// already covered), persist it, and re-check authorization. No network activity.
    AuthorizeTarget {
        workspace_id: Id,
        target_id: Id,
    },
    /// Start a typed provider installation (async; observe via install_status). The
    /// method and provider id are typed; no caller-supplied command is executed.
    StartInstall {
        provider_id: String,
        method: crate::install::InstallMethod,
    },
    /// Request cancellation of a running installation.
    CancelInstall {},
    /// Read-only install status (running provider/method + last outcome).
    InstallStatus {},
    /// Record an analyst's evidence-backed correlation proposal between two assets
    /// (Issue #67). Never merges or modifies assets; starts PROPOSED.
    ProposeCorrelation {
        workspace_id: Id,
        #[serde(flatten)]
        proposal: crate::correlation::Proposal,
    },
    /// Apply an explicit review decision (confirm/reject/retract/reopen) with a note.
    ReviewCorrelation {
        workspace_id: Id,
        correlation_id: Id,
        decision: crate::correlation::ReviewDecision,
        note: String,
    },
    /// Create a durable analyst Finding (Issue #76). Only the analyst's conclusion; any
    /// asset/evidence/source references must already exist in this workspace.
    CreateFinding {
        workspace_id: Id,
        finding: crate::findings::NewFinding,
    },
    /// Edit a Finding's analyst-controlled fields (not status, not source attribution).
    UpdateFinding {
        workspace_id: Id,
        finding_id: Id,
        edit: crate::findings::FindingEdit,
    },
    /// Apply a validated lifecycle transition with a note.
    SetFindingStatus {
        workspace_id: Id,
        finding_id: Id,
        status: crate::findings::FindingStatus,
        note: String,
    },
    /// Attach an existing evidence record to a Finding (idempotent, same-workspace).
    LinkFindingEvidence {
        workspace_id: Id,
        finding_id: Id,
        evidence_id: Id,
    },
    /// Detach an evidence record from a Finding (the Evidence itself is untouched).
    UnlinkFindingEvidence {
        workspace_id: Id,
        finding_id: Id,
        evidence_id: Id,
    },
    /// Read-only normalized result projection for a chain's durable records (typed
    /// result items with provenance). The shared results contract; never raw stdout.
    ResultProjection {
        workspace_id: Id,
        chain_id: Id,
    },
    /// Read-only: build a deterministic, non-persisted Finding draft from a validated
    /// selection of durable context (results/assets/evidence/run). No Finding is created;
    /// the analyst persists it with `create_finding`. No network activity.
    DraftFinding {
        workspace_id: Id,
        context: crate::draft::DraftContext,
    },
}

impl Command {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Hello { .. } => "hello",
            Self::ListWorkspaces { .. } => "list_workspaces",
            Self::CreateWorkspace { .. } => "create_workspace",
            Self::UpdateWorkspaceScope { .. } => "update_workspace_scope",
            Self::AddTarget { .. } => "add_target",
            Self::Snapshot { .. } => "snapshot",
            Self::ChainResults { .. } => "chain_results",
            Self::EventsAfter { .. } => "events_after",
            Self::StartChain { .. } => "start_chain",
            Self::CancelChain { .. } => "cancel_chain",
            Self::ReadEvidence { .. } => "read_evidence",
            Self::ListProviders { .. } => "list_providers",
            Self::TargetScopeStatus { .. } => "target_scope_status",
            Self::AuthorizeTarget { .. } => "authorize_target",
            Self::StartInstall { .. } => "start_install",
            Self::CancelInstall { .. } => "cancel_install",
            Self::InstallStatus { .. } => "install_status",
            Self::ProposeCorrelation { .. } => "propose_correlation",
            Self::ReviewCorrelation { .. } => "review_correlation",
            Self::CreateFinding { .. } => "create_finding",
            Self::UpdateFinding { .. } => "update_finding",
            Self::SetFindingStatus { .. } => "set_finding_status",
            Self::LinkFindingEvidence { .. } => "link_finding_evidence",
            Self::UnlinkFindingEvidence { .. } => "unlink_finding_evidence",
            Self::ResultProjection { .. } => "result_projection",
            Self::DraftFinding { .. } => "draft_finding",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub protocol_version: u32,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<CoreError>,
}

impl Response {
    pub fn failure(id: String, error: CoreError) -> Self {
        Self {
            protocol_version: VERSION,
            request_id: id,
            result: None,
            error: Some(error),
        }
    }
}

pub fn handle(engine: &Engine, request: Request) -> Response {
    let id = request.request_id;
    if request.protocol_version != VERSION
        || id.len() > 64
        || id.is_empty()
        || id.chars().any(char::is_control)
    {
        return Response::failure(
            id,
            CoreError::new(
                "ProtocolMismatch",
                "Unsupported protocol version or request identity.",
            ),
        );
    }
    let result: Result<Value> = (|| {
        Ok(match request.command {
            Command::Hello {} => {
                json!({"core_version":env!("CARGO_PKG_VERSION"),"protocol_version":VERSION,"offline_only":false})
            }
            Command::ListWorkspaces {} => serde_json::to_value(engine.store.list_workspaces()?)?,
            Command::CreateWorkspace { name, scope } => {
                serde_json::to_value(engine.store.create_workspace(&name, &scope)?)?
            }
            Command::UpdateWorkspaceScope {
                workspace_id,
                scope,
            } => serde_json::to_value(engine.store.update_workspace_scope(workspace_id, &scope)?)?,
            Command::AddTarget {
                workspace_id,
                value,
            } => serde_json::to_value(engine.store.add_target(workspace_id, &value)?)?,
            Command::Snapshot { workspace_id } => {
                serde_json::to_value(engine.store.snapshot(workspace_id)?)?
            }
            Command::ChainResults {
                workspace_id,
                chain_id,
            } => serde_json::to_value(engine.store.chain_results(workspace_id, chain_id)?)?,
            Command::EventsAfter {
                workspace_id,
                after,
            } => serde_json::to_value(engine.store.events_after(workspace_id, after)?)?,
            Command::StartChain {
                workspace_id,
                target_id,
                chain,
                options,
            } => serde_json::to_value(engine.start(workspace_id, target_id, chain, options)?)?,
            Command::CancelChain {
                workspace_id,
                chain_id,
            } => {
                engine.cancel(workspace_id, chain_id)?;
                json!({"cancelled":true})
            }
            Command::ReadEvidence {
                workspace_id,
                evidence_id,
            } => {
                json!({"evidence_id":evidence_id,"raw_json":engine.store.read_evidence(workspace_id,evidence_id)?})
            }
            Command::ListProviders {} => serde_json::to_value(engine.providers())?,
            Command::TargetScopeStatus {
                workspace_id,
                target_id,
            } => serde_json::to_value(engine.store.target_scope_status(workspace_id, target_id)?)?,
            Command::AuthorizeTarget {
                workspace_id,
                target_id,
            } => serde_json::to_value(engine.store.authorize_target(workspace_id, target_id)?)?,
            Command::StartInstall {
                provider_id,
                method,
            } => engine.start_install(&provider_id, method)?,
            Command::CancelInstall {} => {
                engine.cancel_install()?;
                json!({"cancelled": true})
            }
            Command::InstallStatus {} => engine.install_status()?,
            Command::ProposeCorrelation {
                workspace_id,
                proposal,
            } => serde_json::to_value(engine.store.propose_correlation(workspace_id, proposal)?)?,
            Command::ReviewCorrelation {
                workspace_id,
                correlation_id,
                decision,
                note,
            } => serde_json::to_value(engine.store.review_correlation(
                workspace_id,
                correlation_id,
                decision,
                &note,
            )?)?,
            Command::CreateFinding {
                workspace_id,
                finding,
            } => serde_json::to_value(engine.store.create_finding(workspace_id, finding)?)?,
            Command::UpdateFinding {
                workspace_id,
                finding_id,
                edit,
            } => serde_json::to_value(engine.store.update_finding(
                workspace_id,
                finding_id,
                edit,
            )?)?,
            Command::SetFindingStatus {
                workspace_id,
                finding_id,
                status,
                note,
            } => serde_json::to_value(engine.store.set_finding_status(
                workspace_id,
                finding_id,
                status,
                &note,
            )?)?,
            Command::LinkFindingEvidence {
                workspace_id,
                finding_id,
                evidence_id,
            } => serde_json::to_value(engine.store.link_finding_evidence(
                workspace_id,
                finding_id,
                evidence_id,
            )?)?,
            Command::UnlinkFindingEvidence {
                workspace_id,
                finding_id,
                evidence_id,
            } => serde_json::to_value(engine.store.unlink_finding_evidence(
                workspace_id,
                finding_id,
                evidence_id,
            )?)?,
            Command::ResultProjection {
                workspace_id,
                chain_id,
            } => serde_json::to_value(engine.store.result_projection(workspace_id, chain_id)?)?,
            Command::DraftFinding {
                workspace_id,
                context,
            } => serde_json::to_value(engine.store.draft_finding(workspace_id, context)?)?,
        })
    })();
    match result {
        Ok(result) => Response {
            protocol_version: VERSION,
            request_id: id,
            result: Some(result),
            error: None,
        },
        Err(error) => Response::failure(id, error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protocol_version_and_typed_errors_cross_boundary() {
        let temp = tempfile::tempdir().unwrap();
        let engine = Engine::open(
            crate::database::Store::open(temp.path()).unwrap(),
            std::time::Duration::ZERO,
        )
        .unwrap();
        let response = handle(
            &engine,
            Request {
                protocol_version: 99,
                request_id: "test".into(),
                command: Command::Hello {},
            },
        );
        assert_eq!(response.error.unwrap().code, "ProtocolMismatch");
        let response = handle(
            &engine,
            Request {
                protocol_version: 1,
                request_id: "test".into(),
                command: Command::Snapshot {
                    workspace_id: Id::new_v4(),
                },
            },
        );
        assert_eq!(response.error.unwrap().code, "WorkspaceNotFound");
    }
    #[test]
    fn protocol_updates_workspace_scope() {
        let temp = tempfile::tempdir().unwrap();
        let engine = Engine::open(
            crate::database::Store::open(temp.path()).unwrap(),
            std::time::Duration::ZERO,
        )
        .unwrap();
        let workspace = engine
            .store
            .create_workspace("Scope test", &["example.test".into()])
            .unwrap();

        let response = handle(
            &engine,
            Request {
                protocol_version: 1,
                request_id: "scope-update".into(),
                command: Command::UpdateWorkspaceScope {
                    workspace_id: workspace.id,
                    scope: vec!["example.com".into(), "*.example.com".into()],
                },
            },
        );
        assert!(response.error.is_none());
        assert_eq!(
            engine.store.workspace(workspace.id).unwrap().scope,
            vec!["*.example.com".to_string(), "example.com".to_string()]
        );
    }

    #[test]
    fn wire_accepts_osint_chain_kinds_and_provider_option() {
        for (wire, kind) in [
            (
                "username_osint",
                crate::orchestration::ChainKind::UsernameOsint,
            ),
            ("email_osint", crate::orchestration::ChainKind::EmailOsint),
            ("phone_osint", crate::orchestration::ChainKind::PhoneOsint),
            ("domain_osint", crate::orchestration::ChainKind::DomainOsint),
        ] {
            let request: Request = serde_json::from_value(
                json!({"protocol_version":1,"request_id":"osint","method":"start_chain","params":{
                "workspace_id": Id::new_v4(), "target_id": Id::new_v4(), "chain": wire,
                "options": {"provider_id": "user_scanner"}}}),
            )
            .unwrap();
            let Command::StartChain { chain, options, .. } = request.command else {
                panic!("not start_chain")
            };
            assert_eq!(chain, kind);
            assert_eq!(options["provider_id"], "user_scanner");
        }
    }

    #[test]
    fn wire_rejects_invalid_uuid_and_unknown_method() {
        assert!(serde_json::from_value::<Request>(json!({"protocol_version":1,"request_id":"test","method":"snapshot","params":{"workspace_id":"../outside"}})).is_err());
        assert!(serde_json::from_value::<Request>(
            json!({"protocol_version":1,"request_id":"test","method":"execute_shell","params":{}})
        )
        .is_err());
    }
}
