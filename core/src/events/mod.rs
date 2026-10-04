use crate::assets::Id;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    WorkspaceCreated,
    WorkspaceScopeUpdated,
    TargetAdded,
    AssetDiscovered,
    RelationshipCreated,
    ChainStarted,
    ChainStageStarted,
    ChainStageCompleted,
    ProviderStarted,
    /// Display-only sanitized command (executable basename + argument array) for the
    /// live console. Never a shell string; carries no environment or secrets.
    ProviderCommand,
    ProviderCompleted,
    EvidenceCreated,
    TaskStatusChanged,
    ChainCompleted,
    ReconCancelled,
    RecoveryCompleted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: Id,
    pub workspace_id: Id,
    pub sequence: i64,
    pub timestamp: String,
    pub event_type: EventType,
    pub payload: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskStatus {
    Queued,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

impl TaskStatus {
    pub fn can_transition(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Queued, Self::Running | Self::Cancelled | Self::Failed)
                | (
                    Self::Running,
                    Self::Paused | Self::Completed | Self::Failed | Self::Cancelled
                )
                | (Self::Paused, Self::Running | Self::Failed | Self::Cancelled)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChainStatus {
    Pending,
    Running,
    Completed,
    Partial,
    Failed,
    Cancelled,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_tasks_cannot_restart() {
        assert!(TaskStatus::Queued.can_transition(TaskStatus::Running));
        assert!(TaskStatus::Running.can_transition(TaskStatus::Completed));
        assert!(!TaskStatus::Completed.can_transition(TaskStatus::Running));
        assert!(!TaskStatus::Cancelled.can_transition(TaskStatus::Running));
        assert!(!TaskStatus::Queued.can_transition(TaskStatus::Completed));
    }
}
