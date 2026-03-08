//! HeadersClient chain tracker implementation.
//!
//! Verifies Merkle roots by POSTing to a Block Headers Service endpoint
//! at `/api/v1/chain/merkleroot/verify`.

use async_trait::async_trait;
use reqwest::Client;

use crate::transaction::chain_tracker::ChainTracker;
use crate::transaction::error::TransactionError;

/// HeadersClient chain tracker that validates Merkle roots via a Block Headers Service.
pub struct HeadersClient {
    url: String,
    api_key: Option<String>,
    client: Client,
}

impl HeadersClient {
    /// Create a new HeadersClient with the given base URL and optional API key.
    pub fn new(url: &str, api_key: Option<String>) -> Self {
        Self {
            url: url.trim_end_matches('/').to_string(),
            api_key,
            client: Client::new(),
        }
    }
}

#[async_trait]
impl ChainTracker for HeadersClient {
    async fn is_valid_root_for_height(
        &self,
        root: &str,
        height: u32,
    ) -> Result<bool, TransactionError> {
        let url = format!("{}/api/v1/chain/merkleroot/verify", self.url);

        let body = serde_json::json!([{
            "merkleroot": root,
            "blockHeight": height
        }]);

        let mut request = self.client.post(&url).json(&body);

        if let Some(ref key) = self.api_key {
            request = request.header("Authorization", format!("Bearer {}", key));
        }

        let response = request
            .send()
            .await
            .map_err(|e| TransactionError::InvalidFormat(format!("network error: {}", e)))?;

        if !response.status().is_success() {
            return Err(TransactionError::InvalidFormat(format!(
                "HTTP {} from headers client",
                response.status()
            )));
        }

        let body: serde_json::Value = response.json().await.map_err(|e| {
            TransactionError::InvalidFormat(format!("failed to parse response: {}", e))
        })?;

        // The response is expected to be an object with a "confirmationState" field,
        // or an array of verification results. Handle both forms.
        if let Some(state) = body["confirmationState"].as_str() {
            Ok(state == "CONFIRMED")
        } else if let Some(arr) = body.as_array() {
            // Array of results: check first element
            if let Some(first) = arr.first() {
                let confirmed = first["confirmationState"]
                    .as_str()
                    .map(|s| s == "CONFIRMED")
                    .unwrap_or(false);
                Ok(confirmed)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_headers_client_verify_confirmed() {
        let mock_server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chain/merkleroot/verify"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "confirmationState": "CONFIRMED"
            })))
            .mount(&mock_server)
            .await;

        let client = HeadersClient::new(&mock_server.uri(), None);
        let result = client
            .is_valid_root_for_height("abcdef1234567890", 100000)
            .await;

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_headers_client_verify_not_confirmed() {
        let mock_server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chain/merkleroot/verify"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "confirmationState": "UNCONFIRMED"
            })))
            .mount(&mock_server)
            .await;

        let client = HeadersClient::new(&mock_server.uri(), None);
        let result = client
            .is_valid_root_for_height("abcdef1234567890", 100000)
            .await;

        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_headers_client_verify_with_api_key() {
        let mock_server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chain/merkleroot/verify"))
            .and(matchers::header("Authorization", "Bearer test-api-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "confirmationState": "CONFIRMED"
            })))
            .mount(&mock_server)
            .await;

        let client = HeadersClient::new(&mock_server.uri(), Some("test-api-key".to_string()));
        let result = client
            .is_valid_root_for_height("abcdef1234567890", 100000)
            .await;

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_headers_client_http_error() {
        let mock_server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chain/merkleroot/verify"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let client = HeadersClient::new(&mock_server.uri(), None);
        let result = client.is_valid_root_for_height("abcdef", 100000).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_headers_client_array_response() {
        let mock_server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/api/v1/chain/merkleroot/verify"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {
                    "merkleroot": "abcdef1234567890",
                    "blockHeight": 100000,
                    "confirmationState": "CONFIRMED"
                }
            ])))
            .mount(&mock_server)
            .await;

        let client = HeadersClient::new(&mock_server.uri(), None);
        let result = client
            .is_valid_root_for_height("abcdef1234567890", 100000)
            .await;

        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}
