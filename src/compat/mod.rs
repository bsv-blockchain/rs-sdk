//! Compatibility layer for legacy Bitcoin protocols.
//!
//! Implements BIP32 (HD wallets), BIP39 (mnemonics), BSM (signed messages),
//! and ECIES (encryption). These are backward-compatibility features;
//! the preferred modern equivalents are BRC-42/43/77/78.

pub mod bip32;
pub mod bip39;
pub mod bip39_wordlists;
pub mod bsm;
pub mod ecies;
pub mod error;

pub use error::CompatError;
