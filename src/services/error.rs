//! Error types for the services module.

use thiserror::Error;

/// Unified error type for all service operations.
#[derive(Debug, Error)]
pub enum ServicesError {
    /// Identity service error.
    #[error("identity error: {0}")]
    Identity(String),

    /// Registry service error.
    #[error("registry error: {0}")]
    Registry(String),

    /// Storage service error.
    #[error("storage error: {0}")]
    Storage(String),

    /// Key-value store service error.
    #[error("kvstore error: {0}")]
    KvStore(String),

    /// Messages (BRC-77/78) error.
    #[error("messages error: {0}")]
    Messages(String),

    /// Overlay tools error.
    #[error("overlay error: {0}")]
    Overlay(String),

    /// HTTP transport error.
    #[error("http error: {0}")]
    Http(String),

    /// Serialization/deserialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Error from the auth layer.
    #[error("auth error: {0}")]
    Auth(#[from] crate::auth::error::AuthError),

    /// Error from the wallet layer.
    #[error("wallet error: {0}")]
    Wallet(#[from] crate::wallet::WalletError),

    /// Error from the primitives layer.
    #[error("primitives error: {0}")]
    Primitives(#[from] crate::primitives::PrimitivesError),
}
