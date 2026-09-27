use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreError {
    pub code: String,
    pub message: String,
}

pub type Result<T> = std::result::Result<T, CoreError>;

impl CoreError {
    pub fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for CoreError {}
impl From<rusqlite::Error> for CoreError {
    fn from(_: rusqlite::Error) -> Self {
        Self::new("DatabaseError", "The workspace database operation failed.")
    }
}
impl From<std::io::Error> for CoreError {
    fn from(_: std::io::Error) -> Self {
        Self::new("StorageError", "The application storage operation failed.")
    }
}
impl From<serde_json::Error> for CoreError {
    fn from(_: serde_json::Error) -> Self {
        Self::new(
            "InvalidData",
            "Structured data did not match the expected format.",
        )
    }
}
