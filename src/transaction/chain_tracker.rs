//! ChainTracker trait for verifying Merkle roots against the blockchain.

use crate::transaction::error::TransactionError;
use async_trait::async_trait;

/// Trait for verifying Merkle roots against the blockchain.
///
/// Implementations query a network service to determine whether a given Merkle root
/// is valid for a specific block height and optionally return the current chain tip.
#[async_trait]
pub trait ChainTracker: Send + Sync {
    /// Check if a Merkle root is valid for the given block height.
    async fn is_valid_root_for_height(
        &self,
        root: &str,
        height: u32,
    ) -> Result<bool, TransactionError>;

    /// Get the current chain tip height (optional, default returns error).
    async fn current_height(&self) -> Result<u32, TransactionError> {
        Err(TransactionError::InvalidFormat(
            "current_height not implemented".to_string(),
        ))
    }
}
