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
    AddTarget {
        workspace_id: Id,
        value: String,
    },
    Snapshot {
        workspace_id: Id,
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
}

impl Command {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Hello { .. } => "hello",
            Self::ListWorkspaces { .. } => "list_workspaces",
            Self::CreateWorkspace { .. } => "create_workspace",
            Self::AddTarget { .. } => "add_target",
            Self::Snapshot { .. } => "snapshot",
            Self::EventsAfter { .. } => "events_after",
            Self::StartChain { .. } => "start_chain",
            Self::CancelChain { .. } => "cancel_chain",
            Self::ReadEvidence { .. } => "read_evidence",
            Self::ListProviders { .. } => "list_providers",
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
                json!({"core_version":env!("CARGO_PKG_VERSION"),"protocol_version":VERSION,"offline_only":true})
            }
            Command::ListWorkspaces {} => serde_json::to_value(engine.store.list_workspaces()?)?,
            Command::CreateWorkspace { name, scope } => {
                serde_json::to_value(engine.store.create_workspace(&name, &scope)?)?
            }
            Command::AddTarget {
                workspace_id,
                value,
            } => serde_json::to_value(engine.store.add_target(workspace_id, &value)?)?,
            Command::Snapshot { workspace_id } => {
                serde_json::to_value(engine.store.snapshot(workspace_id)?)?
            }
            Command::EventsAfter {
                workspace_id,
                after,
            } => serde_json::to_value(engine.store.events_after(workspace_id, after)?)?,
            Command::StartChain {
                workspace_id,
                target_id,
                chain,
            } => serde_json::to_value(engine.start(workspace_id, target_id, chain)?)?,
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
    fn wire_rejects_invalid_uuid_and_unknown_method() {
        assert!(serde_json::from_value::<Request>(json!({"protocol_version":1,"request_id":"test","method":"snapshot","params":{"workspace_id":"../outside"}})).is_err());
        assert!(serde_json::from_value::<Request>(
            json!({"protocol_version":1,"request_id":"test","method":"execute_shell","params":{}})
        )
        .is_err());
    }
}
