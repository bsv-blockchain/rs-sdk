//! Error types for the compatibility layer.

use crate::primitives::error::PrimitivesError;
use thiserror::Error;

/// Error type for all compatibility layer operations.
#[derive(Debug, Error)]
pub enum CompatError {
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("invalid entropy: {0}")]
    InvalidEntropy(String),

    #[error("invalid extended key: {0}")]
    InvalidExtendedKey(String),

    #[error("cannot derive hardened child from public key")]
    HardenedFromPublic,

    #[error("derivation depth exceeded (max 255)")]
    DepthExceeded,

    #[error("invalid derivation path: {0}")]
    InvalidPath(String),

    #[error("invalid child key")]
    InvalidChild,

    #[error("unusable seed")]
    UnusableSeed,

    #[error("checksum mismatch")]
    ChecksumMismatch,

    #[error("invalid magic bytes")]
    InvalidMagic,

    #[error("HMAC verification failed")]
    HmacMismatch,

    #[error("invalid ciphertext: {0}")]
    InvalidCiphertext(String),

    #[error("sender public key required")]
    SenderKeyRequired,

    #[error("recovery failed: {0}")]
    RecoveryFailed(String),

    #[error("primitives error: {0}")]
    Primitives(#[from] PrimitivesError),
}
