//! WhatsOnChain chain tracker implementation.
//!
//! Verifies Merkle roots by querying the WhatsOnChain API for block headers
//! and comparing the `merkleroot` field.

use async_trait::async_trait;
use reqwest::Client;

use crate::transaction::chain_tracker::ChainTracker;
use crate::transaction::error::TransactionError;

/// WhatsOnChain chain tracker that validates Merkle roots via the WoC API.
pub struct WhatsOnChainTracker {
    #[allow(dead_code)]
    network: String,
    base_url: String,
    client: Client,
}

impl WhatsOnChainTracker {
    /// Create a new WhatsOnChain chain tracker for the given network ("main" or "test").
    pub fn new(network: &str) -> Self {
        Self {
            network: network.to_string(),
            base_url: format!("https://api.whatsonchain.com/v1/bsv/{}", network),
            client: Client::new(),
        }
    }

    /// Create with a custom base URL (for testing with mock servers).
    pub fn with_url(network: &str, base_url: &str) -> Self {
        Self {
            network: network.to_string(),
            base_url: base_url.trim_end_matches('/').to_string(),
            client: Client::new(),
        }
    }
}

#[async_trait]
impl ChainTracker for WhatsOnChainTracker {
    async fn is_valid_root_for_height(
        &self,
        root: &str,
        height: u32,
    ) -> Result<bool, TransactionError> {
        let url = format!("{}/block/{}/header", self.base_url, height);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| TransactionError::InvalidFormat(format!("network error: {}", e)))?;

        if !response.status().is_success() {
            return Err(TransactionError::InvalidFormat(format!(
                "HTTP {} from chain tracker",
                response.status()
            )));
        }

        let body: serde_json::Value = response.json().await.map_err(|e| {
            TransactionError::InvalidFormat(format!("failed to parse response: {}", e))
        })?;

        let merkle_root = body["merkleroot"].as_str().unwrap_or("");

        Ok(merkle_root == root)
    }

    async fn current_height(&self) -> Result<u32, TransactionError> {
        let url = format!("{}/chain/info", self.base_url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| TransactionError::InvalidFormat(format!("network error: {}", e)))?;

        if !response.status().is_success() {
            return Err(TransactionError::InvalidFormat(format!(
                "HTTP {} from chain tracker",
                response.status()
            )));
        }

        let body: serde_json::Value = response.json().await.map_err(|e| {
            TransactionError::InvalidFormat(format!("failed to parse response: {}", e))
        })?;

        body["blocks"].as_u64().map(|h| h as u32).ok_or_else(|| {
            TransactionError::InvalidFormat("missing blocks field in chain info".to_string())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_is_valid_root_for_height_success() {
        let mock_server = MockServer::start().await;

        Mock::given(matchers::method("GET"))
            .and(matchers::path("/block/100000/header"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "merkleroot": "abcdef1234567890",
                "hash": "000000000000...",
                "height": 100000
            })))
            .mount(&mock_server)
            .await;

        let tracker = WhatsOnChainTracker::with_url("main", &mock_server.uri());
        let result = tracker
            .is_valid_root_for_height("abcdef1234567890", 100000)
            .await;

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_is_valid_root_for_height_mismatch() {
        let mock_server = MockServer::start().await;

        Mock::given(matchers::method("GET"))
            .and(matchers::path("/block/100000/header"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "merkleroot": "different_root",
                "hash": "000000000000...",
                "height": 100000
            })))
            .mount(&mock_server)
            .await;

        let tracker = WhatsOnChainTracker::with_url("main", &mock_server.uri());
        let result = tracker
            .is_valid_root_for_height("abcdef1234567890", 100000)
            .await;

        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_current_height() {
        let mock_server = MockServer::start().await;

        Mock::given(matchers::method("GET"))
            .and(matchers::path("/chain/info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "blocks": 850000,
                "chain": "main"
            })))
            .mount(&mock_server)
            .await;

        let tracker = WhatsOnChainTracker::with_url("main", &mock_server.uri());
        let result = tracker.current_height().await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 850000);
    }

    #[tokio::test]
    async fn test_is_valid_root_http_error() {
        let mock_server = MockServer::start().await;

        Mock::given(matchers::method("GET"))
            .and(matchers::path("/block/999999/header"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let tracker = WhatsOnChainTracker::with_url("main", &mock_server.uri());
        let result = tracker.is_valid_root_for_height("abcdef", 999999).await;

        assert!(result.is_err());
    }
}
