//! Types for the registry service module.
//!
//! Translates the TS SDK registry/types/index.ts.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::wallet::types::Protocol;

/// Registry definition types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefinitionType {
    /// Basket-based definition.
    Basket,
    /// Protocol-based definition.
    Protocol,
    /// Certificate-based definition.
    Certificate,
}

/// Describes a certificate field for the CertMap registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateFieldDescriptor {
    /// Human-friendly name.
    pub friendly_name: String,
    /// Field description.
    pub description: String,
    /// Field data type.
    #[serde(rename = "type")]
    pub field_type: String,
    /// Icon for this field.
    pub field_icon: String,
}

/// Registry data for a Basket-style record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasketDefinitionData {
    pub basket_id: String,
    pub name: String,
    pub icon_url: String,
    pub description: String,
    pub documentation_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_operator: Option<String>,
}

/// Registry data for a Protocol-style record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolDefinitionData {
    pub protocol_id: Protocol,
    pub name: String,
    pub icon_url: String,
    pub description: String,
    pub documentation_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_operator: Option<String>,
}

/// Registry data for a Certificate-style record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateDefinitionData {
    /// Certificate type identifier.
    #[serde(rename = "type")]
    pub cert_type: String,
    pub name: String,
    pub icon_url: String,
    pub description: String,
    pub documentation_url: String,
    pub fields: HashMap<String, CertificateFieldDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_operator: Option<String>,
}

/// Union of all possible definition data objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "definitionType", rename_all = "lowercase")]
pub enum DefinitionData {
    Basket(BasketDefinitionData),
    Protocol(ProtocolDefinitionData),
    Certificate(CertificateDefinitionData),
}

impl DefinitionData {
    /// Get the definition type.
    pub fn definition_type(&self) -> DefinitionType {
        match self {
            DefinitionData::Basket(_) => DefinitionType::Basket,
            DefinitionData::Protocol(_) => DefinitionType::Protocol,
            DefinitionData::Certificate(_) => DefinitionType::Certificate,
        }
    }

    /// Get the name of this definition.
    pub fn name(&self) -> &str {
        match self {
            DefinitionData::Basket(d) => &d.name,
            DefinitionData::Protocol(d) => &d.name,
            DefinitionData::Certificate(d) => &d.name,
        }
    }

    /// Get the registry operator, if set.
    pub fn registry_operator(&self) -> Option<&str> {
        match self {
            DefinitionData::Basket(d) => d.registry_operator.as_deref(),
            DefinitionData::Protocol(d) => d.registry_operator.as_deref(),
            DefinitionData::Certificate(d) => d.registry_operator.as_deref(),
        }
    }

    /// Set the registry operator.
    pub fn set_registry_operator(&mut self, operator: String) {
        match self {
            DefinitionData::Basket(d) => d.registry_operator = Some(operator),
            DefinitionData::Protocol(d) => d.registry_operator = Some(operator),
            DefinitionData::Certificate(d) => d.registry_operator = Some(operator),
        }
    }
}

/// On-chain token data for a registry UTXO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenData {
    /// Transaction ID.
    pub txid: String,
    /// Output index within the transaction.
    pub output_index: u32,
    /// Satoshis held in this output.
    pub satoshis: u64,
    /// Hex-encoded locking script.
    pub locking_script: String,
    /// BEEF-encoded transaction bytes.
    pub beef: Vec<u8>,
}

/// A registry record combining definition data with on-chain token data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryRecord {
    /// The definition data.
    pub data: DefinitionData,
    /// The on-chain token data (present for records from listOwnRegistryEntries).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<TokenData>,
}

/// Configuration options for the RegistryClient.
#[derive(Debug, Clone, Default)]
pub struct RegistryClientOptions {
    /// Whether to accept delayed broadcast.
    pub accept_delayed_broadcast: bool,
}

/// Query for basket definitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasketQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basket_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_operators: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Query for protocol definitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_operators: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_id: Option<Protocol>,
}

/// Query for certificate definitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "type")]
    pub cert_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_operators: Option<Vec<String>>,
}

/// Constants for registry token amounts and key IDs.
pub const REGISTRANT_TOKEN_AMOUNT: u64 = 1;
pub const REGISTRANT_KEY_ID: &str = "1";

/// Map a DefinitionType to the wallet protocol.
pub fn definition_type_to_protocol(dt: &DefinitionType) -> Protocol {
    match dt {
        DefinitionType::Basket => Protocol {
            security_level: 1,
            protocol: "basketmap".to_string(),
        },
        DefinitionType::Protocol => Protocol {
            security_level: 1,
            protocol: "protomap".to_string(),
        },
        DefinitionType::Certificate => Protocol {
            security_level: 1,
            protocol: "certmap".to_string(),
        },
    }
}

/// Map a DefinitionType to the basket name.
pub fn definition_type_to_basket(dt: &DefinitionType) -> &'static str {
    match dt {
        DefinitionType::Basket => "basketmap",
        DefinitionType::Protocol => "protomap",
        DefinitionType::Certificate => "certmap",
    }
}

/// Map a DefinitionType to the broadcast topic.
pub fn definition_type_to_topic(dt: &DefinitionType) -> &'static str {
    match dt {
        DefinitionType::Basket => "tm_basketmap",
        DefinitionType::Protocol => "tm_protomap",
        DefinitionType::Certificate => "tm_certmap",
    }
}

/// Map a DefinitionType to the lookup service name.
pub fn definition_type_to_service(dt: &DefinitionType) -> &'static str {
    match dt {
        DefinitionType::Basket => "ls_basketmap",
        DefinitionType::Protocol => "ls_protomap",
        DefinitionType::Certificate => "ls_certmap",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_definition_type_serde() {
        let dt = DefinitionType::Basket;
        let json = serde_json::to_string(&dt).unwrap();
        assert_eq!(json, "\"basket\"");

        let parsed: DefinitionType = serde_json::from_str("\"certificate\"").unwrap();
        assert_eq!(parsed, DefinitionType::Certificate);
    }

    #[test]
    fn test_basket_definition_data() {
        let data = BasketDefinitionData {
            basket_id: "test-basket".to_string(),
            name: "Test Basket".to_string(),
            icon_url: "https://example.com/icon.png".to_string(),
            description: "A test basket".to_string(),
            documentation_url: "https://example.com/docs".to_string(),
            registry_operator: Some("02abc123".to_string()),
        };
        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("test-basket"));
        let decoded: BasketDefinitionData = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.basket_id, "test-basket");
    }

    #[test]
    fn test_definition_data_union_basket() {
        let data = DefinitionData::Basket(BasketDefinitionData {
            basket_id: "b1".to_string(),
            name: "Basket One".to_string(),
            icon_url: "icon".to_string(),
            description: "desc".to_string(),
            documentation_url: "doc".to_string(),
            registry_operator: None,
        });
        assert_eq!(data.definition_type(), DefinitionType::Basket);
        assert_eq!(data.name(), "Basket One");
        assert!(data.registry_operator().is_none());
    }

    #[test]
    fn test_definition_data_set_operator() {
        let mut data = DefinitionData::Certificate(CertificateDefinitionData {
            cert_type: "test-type".to_string(),
            name: "Test Cert".to_string(),
            icon_url: "icon".to_string(),
            description: "desc".to_string(),
            documentation_url: "doc".to_string(),
            fields: HashMap::new(),
            registry_operator: None,
        });
        data.set_registry_operator("02abc".to_string());
        assert_eq!(data.registry_operator(), Some("02abc"));
    }

    #[test]
    fn test_definition_type_mappings() {
        assert_eq!(
            definition_type_to_basket(&DefinitionType::Basket),
            "basketmap"
        );
        assert_eq!(
            definition_type_to_topic(&DefinitionType::Protocol),
            "tm_protomap"
        );
        assert_eq!(
            definition_type_to_service(&DefinitionType::Certificate),
            "ls_certmap"
        );
    }

    #[test]
    fn test_certificate_field_descriptor() {
        let fd = CertificateFieldDescriptor {
            friendly_name: "First Name".to_string(),
            description: "User's first name".to_string(),
            field_type: "text".to_string(),
            field_icon: "person-icon".to_string(),
        };
        let json = serde_json::to_string(&fd).unwrap();
        assert!(json.contains("First Name"));
        let decoded: CertificateFieldDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.friendly_name, "First Name");
    }

    #[test]
    fn test_registry_record_serialization() {
        let record = RegistryRecord {
            data: DefinitionData::Basket(BasketDefinitionData {
                basket_id: "b1".to_string(),
                name: "Basket".to_string(),
                icon_url: "icon".to_string(),
                description: "desc".to_string(),
                documentation_url: "doc".to_string(),
                registry_operator: Some("op".to_string()),
            }),
            token: Some(TokenData {
                txid: "abc123".to_string(),
                output_index: 0,
                satoshis: 1,
                locking_script: "76a914...".to_string(),
                beef: vec![0x01, 0x02],
            }),
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("abc123"));
    }

    #[test]
    fn test_registry_client_options_default() {
        let opts = RegistryClientOptions::default();
        assert!(!opts.accept_delayed_broadcast);
    }

    #[test]
    fn test_basket_query_serde() {
        let q = BasketQuery {
            basket_id: Some("test".to_string()),
            registry_operators: None,
            name: None,
        };
        let json = serde_json::to_string(&q).unwrap();
        assert!(json.contains("test"));
        assert!(!json.contains("registry_operators"));
    }
}
