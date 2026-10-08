use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

pub type Id = Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetType {
    Domain,
    Subdomain,
    Hostname,
    IPAddress,
    Port,
    Service,
    Website,
    URL,
    Endpoint,
    Technology,
    Certificate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipType {
    HasSubdomain,
    ResolvesTo,
    /// A PTR (reverse-DNS) record: the IP has a PTR pointing at this name. This is a
    /// PTR observation only — it does NOT assert the name's forward records point back
    /// to the IP (that would require a separate forward-confirmation lookup).
    PtrRecord,
    Exposes,
    Serves,
    HasEndpoint,
    UsesTechnology,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub id: Id,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
    pub scope: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub id: Id,
    pub workspace_id: Id,
    pub asset_type: AssetType,
    pub canonical_identity: String,
    pub display_value: String,
    pub metadata: Value,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relationship {
    pub id: Id,
    pub workspace_id: Id,
    pub source_asset_id: Id,
    pub destination_asset_id: Id,
    pub relationship_type: RelationshipType,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub id: Id,
    pub workspace_id: Id,
    pub asset_id: Id,
    pub source_asset_id: Option<Id>,
    pub provider_run_id: Option<Id>,
    pub evidence_id: Option<Id>,
    pub discovered_by: String,
    pub observed_value: String,
    /// Bounded normalized facts emitted for this exact observation/run.
    ///
    /// Asset metadata is the canonical/current asset summary and may not change when
    /// a deduplicated asset is observed again. Historical run results therefore use
    /// this field rather than mutable asset metadata.
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
    pub timestamp: String,
    pub confidence: String,
}

fn empty_metadata() -> Value {
    Value::Object(serde_json::Map::new())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Discovery {
    pub asset_type: AssetType,
    pub value: String,
    pub source: Option<String>,
    pub relationship: Option<RelationshipType>,
    pub metadata: Value,
}

impl Asset {
    /// The value used to decide whether an asset is in workspace scope. Host-child
    /// assets (Port/Service) whose canonical identity is not itself a routable
    /// target are scoped by their `host` metadata (the owning IP); everything else
    /// is scoped by its canonical identity.
    pub fn scope_key(&self) -> &str {
        match self.asset_type {
            AssetType::Port | AssetType::Service => self
                .metadata
                .get("host")
                .and_then(Value::as_str)
                .unwrap_or(&self.canonical_identity),
            _ => &self.canonical_identity,
        }
    }
}

pub fn canonical_identity(kind: AssetType, value: &str) -> crate::error::Result<String> {
    use crate::error::CoreError;
    match kind {
        AssetType::Domain | AssetType::Subdomain | AssetType::Hostname => {
            crate::targets::domain(value)
        }
        AssetType::IPAddress => value
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.to_string())
            .map_err(|_| CoreError::new("InvalidTarget", "Invalid IP address.")),
        AssetType::URL | AssetType::Website | AssetType::Endpoint => crate::targets::web_url(value),
        _ if !value.is_empty() && value.len() <= 2048 && !value.chars().any(char::is_control) => {
            Ok(value.into())
        }
        _ => Err(CoreError::new("InvalidData", "Invalid asset identity.")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn domain_identity_normalizes_case_and_trailing_dot() {
        assert_eq!(
            canonical_identity(AssetType::Subdomain, "API.EXAMPLE.TEST.").unwrap(),
            "api.example.test"
        );
    }
    #[test]
    fn ip_identity_normalizes_ipv6() {
        assert_eq!(
            canonical_identity(AssetType::IPAddress, "2001:0db8::1").unwrap(),
            "2001:db8::1"
        );
    }
}
