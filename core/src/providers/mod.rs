use crate::{
    assets::{Asset, AssetType, Discovery, RelationshipType},
    error::{CoreError, Result},
    targets::TargetType,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskClass {
    Passive,
    ActiveLowImpact,
    Active,
    Validation,
    LabOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Capability {
    SubdomainDiscovery,
    DnsResolution,
    ServiceFingerprinting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderMetadata {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub capabilities: Vec<Capability>,
    pub supported_target_types: Vec<TargetType>,
    pub risk_class: RiskClass,
}

pub trait Provider: Send + Sync {
    fn metadata(&self) -> ProviderMetadata;
    fn execute(&self, target: &str, capability: Capability, inputs: &[Asset]) -> Result<Vec<u8>>;
    fn parse(&self, raw: &[u8]) -> Result<Vec<Discovery>>;
}

#[derive(Clone)]
pub struct ProviderRegistry {
    providers: Vec<Arc<dyn Provider>>,
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self {
            providers: vec![Arc::new(SyntheticDiscoveryProvider)],
        }
    }
}
impl ProviderRegistry {
    pub fn select(
        &self,
        capability: Capability,
        target_type: TargetType,
    ) -> Result<Arc<dyn Provider>> {
        self.providers
            .iter()
            .find(|provider| {
                let metadata = provider.metadata();
                metadata.capabilities.contains(&capability)
                    && metadata.supported_target_types.contains(&target_type)
            })
            .cloned()
            .ok_or_else(|| {
                CoreError::new("ProviderFailure", "No compatible provider is registered.")
            })
    }
    pub fn metadata(&self) -> Vec<ProviderMetadata> {
        self.providers.iter().map(|p| p.metadata()).collect()
    }
}

pub struct SyntheticDiscoveryProvider;

#[derive(Serialize, Deserialize)]
struct SyntheticOutput {
    provider: String,
    input: String,
    capability: Capability,
    synthetic: bool,
    discoveries: Vec<Discovery>,
}

impl Provider for SyntheticDiscoveryProvider {
    fn metadata(&self) -> ProviderMetadata {
        ProviderMetadata {
            id: "synthetic".into(),
            name: "SyntheticDiscoveryProvider".into(),
            description: "Invented offline discoveries. No network, DNS, or external tools.".into(),
            version: "1.0.0".into(),
            risk_class: RiskClass::Passive,
            capabilities: vec![
                Capability::SubdomainDiscovery,
                Capability::DnsResolution,
                Capability::ServiceFingerprinting,
            ],
            supported_target_types: vec![TargetType::Domain],
        }
    }

    fn execute(&self, target: &str, capability: Capability, inputs: &[Asset]) -> Result<Vec<u8>> {
        if target != "example.test" {
            return Err(CoreError::new(
                "ProviderFailure",
                "Phase 0 synthetic recon supports example.test only.",
            ));
        }
        let mut discoveries = Vec::new();
        let mut add = |asset_type, value: String, source: String, relationship, metadata| {
            discoveries.push(Discovery {
                asset_type,
                value,
                source: Some(source),
                relationship: Some(relationship),
                metadata,
            });
        };
        match capability {
            Capability::SubdomainDiscovery => {
                for value in [
                    "api.example.test",
                    "api.example.test",
                    "API.EXAMPLE.TEST",
                    "dev.example.test",
                ] {
                    add(
                        AssetType::Subdomain,
                        value.into(),
                        target.into(),
                        RelationshipType::HasSubdomain,
                        json!({"synthetic":true}),
                    );
                }
            }
            Capability::DnsResolution => {
                for input in inputs
                    .iter()
                    .filter(|a| a.asset_type == AssetType::Subdomain)
                {
                    let address = match input.canonical_identity.as_str() {
                        "api.example.test" => "192.0.2.10",
                        "dev.example.test" => "192.0.2.11",
                        _ => continue,
                    };
                    add(
                        AssetType::IPAddress,
                        address.into(),
                        input.canonical_identity.clone(),
                        RelationshipType::ResolvesTo,
                        json!({"synthetic":true}),
                    );
                }
            }
            Capability::ServiceFingerprinting => {
                for input in inputs
                    .iter()
                    .filter(|a| a.asset_type == AssetType::IPAddress)
                {
                    let ip = input.canonical_identity.as_str();
                    let services = match ip {
                        "192.0.2.10" => vec![(443, "HTTPS")],
                        "192.0.2.11" => vec![(22, "SSH"), (443, "HTTPS")],
                        _ => continue,
                    };
                    for (port, name) in services {
                        let port_id = format!("{ip}/tcp/{port}");
                        add(
                            AssetType::Port,
                            port_id.clone(),
                            ip.into(),
                            RelationshipType::Exposes,
                            json!({"synthetic":true,"host":ip,"port":port,"transport":"tcp"}),
                        );
                        add(
                            AssetType::Service,
                            format!("{port_id}/{}", name.to_lowercase()),
                            port_id,
                            RelationshipType::Serves,
                            json!({"synthetic":true,"host":ip,"name":name}),
                        );
                    }
                }
            }
        }
        Ok(serde_json::to_vec_pretty(&SyntheticOutput {
            provider: "synthetic".into(),
            input: target.into(),
            capability,
            synthetic: true,
            discoveries,
        })?)
    }

    fn parse(&self, raw: &[u8]) -> Result<Vec<Discovery>> {
        if raw.len() > 1024 * 1024 {
            return Err(CoreError::new(
                "ProviderFailure",
                "Provider output exceeds the size budget.",
            ));
        }
        let output: SyntheticOutput = serde_json::from_slice(raw).map_err(|_| {
            CoreError::new("ProviderFailure", "Synthetic provider output is malformed.")
        })?;
        if output.provider != "synthetic"
            || !output.synthetic
            || output.input != "example.test"
            || output.discoveries.len() > 100
        {
            return Err(CoreError::new(
                "ProviderFailure",
                "Synthetic provider output violates its contract.",
            ));
        }
        Ok(output.discoveries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provider_is_passive_and_selected_by_capability() {
        let provider = ProviderRegistry::default()
            .select(Capability::SubdomainDiscovery, TargetType::Domain)
            .unwrap();
        assert_eq!(provider.metadata().risk_class, RiskClass::Passive);
        assert_eq!(provider.metadata().id, "synthetic");
        assert!(ProviderRegistry::default()
            .select(Capability::DnsResolution, TargetType::PhoneNumber)
            .is_err());
    }
    #[test]
    fn synthetic_output_is_structured_and_preserves_observations() {
        let provider = SyntheticDiscoveryProvider;
        let output = provider
            .execute("example.test", Capability::SubdomainDiscovery, &[])
            .unwrap();
        let discoveries = provider.parse(&output).unwrap();
        assert_eq!(discoveries.len(), 4);
        assert_eq!(discoveries[2].value, "API.EXAMPLE.TEST");
    }
    #[test]
    fn malformed_and_non_synthetic_input_fails() {
        assert!(SyntheticDiscoveryProvider.parse(b"not json").is_err());
        assert!(SyntheticDiscoveryProvider
            .execute("example.com", Capability::SubdomainDiscovery, &[])
            .is_err());
    }
}
