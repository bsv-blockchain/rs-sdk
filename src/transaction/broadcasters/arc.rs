//! ARC broadcaster implementation.
//!
//! Broadcasts transactions to an ARC (Bitcoin SV Transaction Processor) service
//! by POSTing the transaction in EF hex format to `/v1/tx`.

use async_trait::async_trait;
use reqwest::Client;

use crate::transaction::broadcaster::{BroadcastFailure, BroadcastResponse, Broadcaster};
use crate::transaction::Transaction;

/// ARC broadcaster that sends transactions to an ARC service endpoint.
pub struct ARC {
    url: String,
    api_key: Option<String>,
    client: Client,
}

impl ARC {
    /// Create a new ARC broadcaster with the given base URL and optional API key.
    pub fn new(url: &str, api_key: Option<String>) -> Self {
        Self {
            url: url.trim_end_matches('/').to_string(),
            api_key,
            client: Client::new(),
        }
    }
}

#[async_trait]
impl Broadcaster for ARC {
    async fn broadcast(&self, tx: &Transaction) -> Result<BroadcastResponse, BroadcastFailure> {
        let ef_hex = tx.to_hex_ef().map_err(|e| BroadcastFailure {
            status: 0,
            code: "SERIALIZE_ERROR".to_string(),
            description: format!("failed to serialize transaction to EF: {}", e),
        })?;

        let mut request = self
            .client
            .post(format!("{}/v1/tx", self.url))
            .header("Content-Type", "application/octet-stream")
            .body(ef_hex);

        if let Some(ref key) = self.api_key {
            request = request.header("X-Api-Key", key);
        }

        let response = request.send().await.map_err(|e| BroadcastFailure {
            status: 0,
            code: "NETWORK_ERROR".to_string(),
            description: format!("network error: {}", e),
        })?;

        let status = response.status().as_u16() as u32;

        if status == 200 || status == 201 {
            let body: serde_json::Value = response.json().await.map_err(|e| BroadcastFailure {
                status,
                code: "PARSE_ERROR".to_string(),
                description: format!("failed to parse response: {}", e),
            })?;

            let txid = body["txid"].as_str().unwrap_or("").to_string();

            Ok(BroadcastResponse {
                status: "success".to_string(),
                txid,
                message: body["message"].as_str().unwrap_or("").to_string(),
            })
        } else {
            let body: serde_json::Value = response.json().await.unwrap_or(serde_json::json!({}));

            Err(BroadcastFailure {
                status,
                code: body["code"].as_str().unwrap_or("UNKNOWN").to_string(),
                description: body["description"]
                    .as_str()
                    .or_else(|| body["message"].as_str())
                    .unwrap_or("unknown error")
                    .to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn make_test_tx() -> Transaction {
        Transaction::new()
    }

    #[tokio::test]
    async fn test_arc_broadcast_success() {
        let mock_server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/tx"))
            .and(matchers::header("Content-Type", "application/octet-stream"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "txid": "abc123def456",
                "message": "Transaction accepted"
            })))
            .mount(&mock_server)
            .await;

        let arc = ARC::new(&mock_server.uri(), None);
        let tx = make_test_tx();
        let result = arc.broadcast(&tx).await;

        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.txid, "abc123def456");
        assert_eq!(resp.status, "success");
        assert_eq!(resp.message, "Transaction accepted");
    }

    #[tokio::test]
    async fn test_arc_broadcast_with_api_key() {
        let mock_server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/tx"))
            .and(matchers::header("X-Api-Key", "test-key-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "txid": "abc123"
            })))
            .mount(&mock_server)
            .await;

        let arc = ARC::new(&mock_server.uri(), Some("test-key-123".to_string()));
        let tx = make_test_tx();
        let result = arc.broadcast(&tx).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_arc_broadcast_failure() {
        let mock_server = MockServer::start().await;

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/tx"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "code": "ERR_BAD_REQUEST",
                "description": "Invalid transaction"
            })))
            .mount(&mock_server)
            .await;

        let arc = ARC::new(&mock_server.uri(), None);
        let tx = make_test_tx();
        let result = arc.broadcast(&tx).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status, 400);
        assert_eq!(err.code, "ERR_BAD_REQUEST");
        assert_eq!(err.description, "Invalid transaction");
    }
}
