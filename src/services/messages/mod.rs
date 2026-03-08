//! BRC-77 Signed Messages and BRC-78 Encrypted Messages.
//!
//! This module provides standalone message signing, verification,
//! encryption, and decryption using only primitives (no network dependency).

pub mod encrypted_message;
pub mod signed_message;

pub use encrypted_message::{decrypt, encrypt};
pub use signed_message::{sign, verify};
