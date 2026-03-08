//! Shared types for overlay tools.
//!
//! Translates the TS SDK overlay-tools types: LookupQuestion, LookupAnswer,
//! TaggedBEEF, STEAK, Network presets, and configuration structs.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Network presets for overlay service discovery.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum Network {
    /// BSV mainnet with production SLAP trackers.
    #[default]
    Mainnet,
    /// BSV testnet with testnet SLAP trackers.
    Testnet,
    /// Local development (localhost:8080).
    Local,
    /// Custom tracker URLs.
    Custom(Vec<String>),
}

impl Network {
    /// Returns the default SLAP tracker URLs for this network preset.
    pub fn default_slap_trackers(&self) -> Vec<String> {
        match self {
            Network::Mainnet => vec![
                "https://overlay-us-1.bsvb.tech".into(),
                "https://overlay-eu-1.bsvb.tech".into(),
                "https://overlay-ap-1.bsvb.tech".into(),
                "https://users.bapp.dev".into(),
            ],
            Network::Testnet => vec!["https://testnet-users.bapp.dev".into()],
            Network::Local => vec!["http://localhost:8080".into()],
            Network::Custom(trackers) => trackers.clone(),
        }
    }
}

/// A question posed to the overlay services engine for lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LookupQuestion {
    /// The identifier for the lookup service to query.
    pub service: String,
    /// The query payload, whose shape depends on the lookup service.
    pub query: serde_json::Value,
}

/// An individual output entry in a lookup answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LookupOutputEntry {
    /// BEEF-encoded transaction bytes.
    pub beef: Vec<u8>,
    /// The output index within the transaction.
    #[serde(rename = "outputIndex")]
    pub output_index: u32,
    /// Optional context bytes associated with this output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Vec<u8>>,
}

/// Response from a lookup query.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum LookupAnswer {
    /// A list of UTXO outputs matching the query.
    #[serde(rename = "output-list")]
    OutputList { outputs: Vec<LookupOutputEntry> },
    /// A freeform result from the lookup service.
    #[serde(rename = "freeform")]
    FreeformResult { result: serde_json::Value },
}

/// Tagged BEEF structure for broadcasting to overlay topics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaggedBEEF {
    /// BEEF-encoded transaction bytes.
    pub beef: Vec<u8>,
    /// Overlay topics for this transaction.
    pub topics: Vec<String>,
}

/// Admittance instructions from a topic manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmittanceInstructions {
    /// Indices of outputs admitted into the managed topic.
    #[serde(rename = "outputsToAdmit")]
    pub outputs_to_admit: Vec<u32>,
    /// Indices of inputs whose spent outputs should be retained.
    #[serde(rename = "coinsToRetain")]
    pub coins_to_retain: Vec<u32>,
    /// Indices of inputs whose previously-admitted outputs were removed.
    #[serde(rename = "coinsRemoved", skip_serializing_if = "Option::is_none")]
    pub coins_removed: Option<Vec<u32>>,
}

/// Submitted Transaction Execution AcKnowledgment (STEAK).
///
/// Maps topic names to admittance instructions.
pub type STEAK = HashMap<String, AdmittanceInstructions>;

/// Acknowledgment mode for topic broadcasting.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum AcknowledgmentMode {
    /// All hosts must acknowledge all topics.
    RequireFromAllHosts,
    /// At least one host must acknowledge all topics.
    #[default]
    RequireFromAny,
    /// Fire-and-forget; do not check acknowledgments.
    DoNotRequire,
}

/// Configuration for the LookupResolver.
#[derive(Debug, Clone)]
pub struct LookupResolverConfig {
    /// Network preset to use.
    pub network: Network,
    /// Custom SLAP tracker URLs (overrides network preset if set).
    pub slap_trackers: Option<Vec<String>>,
    /// Map of service names to override host URLs.
    pub host_overrides: HashMap<String, Vec<String>>,
    /// Map of service names to additional host URLs.
    pub additional_hosts: HashMap<String, Vec<String>>,
    /// Cache TTL in milliseconds (default 5 minutes).
    pub cache_ttl_ms: u64,
    /// Maximum number of cached host entries (default 128).
    pub cache_max_entries: usize,
}

impl Default for LookupResolverConfig {
    fn default() -> Self {
        LookupResolverConfig {
            network: Network::Mainnet,
            slap_trackers: None,
            host_overrides: HashMap::new(),
            additional_hosts: HashMap::new(),
            cache_ttl_ms: 5 * 60 * 1000, // 5 minutes
            cache_max_entries: 128,
        }
    }
}

/// Configuration for the TopicBroadcaster.
#[derive(Debug, Clone)]
pub struct TopicBroadcasterConfig {
    /// Network preset to use.
    pub network: Network,
    /// Acknowledgment mode for broadcasts.
    pub acknowledgment_mode: AcknowledgmentMode,
}

impl Default for TopicBroadcasterConfig {
    fn default() -> Self {
        TopicBroadcasterConfig {
            network: Network::Mainnet,
            acknowledgment_mode: AcknowledgmentMode::RequireFromAny,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_mainnet_trackers() {
        let trackers = Network::Mainnet.default_slap_trackers();
        assert_eq!(trackers.len(), 4);
        assert!(trackers[0].contains("overlay-us-1"));
        assert!(trackers[1].contains("overlay-eu-1"));
        assert!(trackers[2].contains("overlay-ap-1"));
        assert!(trackers[3].contains("users.bapp.dev"));
    }

    #[test]
    fn test_network_testnet_trackers() {
        let trackers = Network::Testnet.default_slap_trackers();
        assert_eq!(trackers.len(), 1);
        assert!(trackers[0].contains("testnet-users.bapp.dev"));
    }

    #[test]
    fn test_network_local_trackers() {
        let trackers = Network::Local.default_slap_trackers();
        assert_eq!(trackers.len(), 1);
        assert_eq!(trackers[0], "http://localhost:8080");
    }

    #[test]
    fn test_network_custom_trackers() {
        let custom = vec!["https://my-tracker.example.com".to_string()];
        let trackers = Network::Custom(custom.clone()).default_slap_trackers();
        assert_eq!(trackers, custom);
    }

    #[test]
    fn test_default_network_is_mainnet() {
        assert_eq!(Network::default(), Network::Mainnet);
    }

    #[test]
    fn test_default_acknowledgment_mode() {
        assert_eq!(
            AcknowledgmentMode::default(),
            AcknowledgmentMode::RequireFromAny
        );
    }
}
