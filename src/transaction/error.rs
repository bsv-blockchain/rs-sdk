//! Error types for the transaction module.

use thiserror::Error;

/// Unified error type for all transaction operations.
#[derive(Debug, Error)]
pub enum TransactionError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid format: {0}")]
    InvalidFormat(String),

    #[error("missing source transaction")]
    MissingSourceTransaction,

    #[error("missing unlocking script")]
    MissingUnlockingScript,

    #[error("missing locking script")]
    MissingLockingScript,

    #[error("invalid sighash: {0}")]
    InvalidSighash(String),

    #[error("signing failed: {0}")]
    SigningFailed(String),

    #[error("fee calculation failed: {0}")]
    FeeCalculationFailed(String),

    #[error("merkle path verification failed: {0}")]
    MerklePathVerificationFailed(String),

    #[error("BEEF error: {0}")]
    BeefError(String),

    #[error("broadcast failed: {0}")]
    BroadcastFailed(String),

    #[error("script error: {0}")]
    Script(#[from] crate::script::error::ScriptError),

    #[error("primitives error: {0}")]
    Primitives(#[from] crate::primitives::error::PrimitivesError),
}
