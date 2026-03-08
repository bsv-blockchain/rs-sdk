//! Broadcaster trait and response types for submitting transactions to the BSV network.

use crate::transaction::Transaction;
use async_trait::async_trait;

/// Response from a successful broadcast.
#[derive(Debug, Clone)]
pub struct BroadcastResponse {
    /// The status of the broadcast (e.g., "success").
    pub status: String,
    /// The txid of the broadcast transaction.
    pub txid: String,
    /// Optional human-readable message.
    pub message: String,
}

/// Failure from a broadcast attempt.
#[derive(Debug, Clone)]
pub struct BroadcastFailure {
    /// HTTP status code (if applicable).
    pub status: u32,
    /// Error code from the service.
    pub code: String,
    /// Human-readable description.
    pub description: String,
}

/// Trait for broadcasting transactions to the BSV network.
///
/// Implementations send a serialized transaction to a network service and return
/// either a success response (containing the txid) or a failure description.
#[async_trait]
pub trait Broadcaster: Send + Sync {
    /// Broadcast the given transaction to the network.
    async fn broadcast(&self, tx: &Transaction) -> Result<BroadcastResponse, BroadcastFailure>;
}
