//! Error types for the script engine module.

use crate::primitives::error::PrimitivesError;
use thiserror::Error;

/// Unified error type for all script operations.
#[derive(Debug, Error)]
pub enum ScriptError {
    #[error("invalid script: {0}")]
    InvalidScript(String),

    #[error("invalid opcode: {0:#04x}")]
    InvalidOpcode(u8),

    #[error("stack underflow")]
    StackUnderflow,

    #[error("invalid stack operation: {0}")]
    InvalidStackOperation(String),

    #[error("memory limit exceeded")]
    MemoryLimitExceeded,

    #[error("script too long")]
    ScriptTooLong,

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("number too large")]
    NumberTooLarge,

    #[error("division by zero")]
    DivisionByZero,

    #[error("verify failed")]
    VerifyFailed,

    #[error("disabled opcode: {0}")]
    DisabledOpcode(String),

    #[error("OP_EQUALVERIFY failed")]
    EqualVerifyFailed,

    #[error("OP_NUMEQUALVERIFY failed")]
    NumEqualVerifyFailed,

    #[error("OP_CHECKSIGVERIFY failed")]
    CheckSigVerifyFailed,

    #[error("OP_CHECKMULTISIGVERIFY failed")]
    CheckMultiSigVerifyFailed,

    #[error("null dummy violation")]
    NullDummyViolation,

    #[error("clean stack violation")]
    CleanStackViolation,

    #[error("push only violation")]
    PushOnlyViolation,

    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("invalid format: {0}")]
    InvalidFormat(String),

    #[error("minimal encoding violation")]
    MinimalEncodingViolation,

    #[error("invalid length: {0}")]
    InvalidLength(String),

    #[error("primitives error: {0}")]
    Primitives(#[from] PrimitivesError),
}
