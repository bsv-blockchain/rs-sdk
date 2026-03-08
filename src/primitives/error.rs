//! Error types for the primitives module.

use thiserror::Error;

/// Unified error type for all primitive operations.
#[derive(Debug, Error)]
pub enum PrimitivesError {
    #[error("invalid hex: {0}")]
    InvalidHex(String),

    #[error("invalid DER: {0}")]
    InvalidDer(String),

    #[error("invalid WIF: {0}")]
    InvalidWif(String),

    #[error("point not on curve")]
    PointNotOnCurve,

    #[error("invalid private key: {0}")]
    InvalidPrivateKey(String),

    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("decryption failed")]
    DecryptionFailed,

    #[error("invalid padding")]
    InvalidPadding,

    #[error("checksum mismatch")]
    ChecksumMismatch,

    #[error("insufficient entropy")]
    InsufficientEntropy,

    #[error("arithmetic error: {0}")]
    ArithmeticError(String),

    #[error("threshold error: {0}")]
    ThresholdError(String),

    #[error("division by zero")]
    DivisionByZero,

    #[error("invalid length: {0}")]
    InvalidLength(String),

    #[error("invalid format: {0}")]
    InvalidFormat(String),
}
