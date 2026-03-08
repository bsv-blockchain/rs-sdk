//! KVStore module for overlay-backed and wallet-backed key-value storage.
//!
//! Provides GlobalKVStore for overlay-backed storage with Historian
//! and double-spend retry, and LocalKVStore for wallet basket-backed
//! storage with per-key locking and optional encryption.

pub mod interpreter;
pub mod types;

#[cfg(feature = "network")]
pub mod global_kvstore;
#[cfg(feature = "network")]
pub mod local_kvstore;

pub use interpreter::kv_store_interpreter;
pub use types::{
    KvContext, KvProtocol, KvStoreConfig, KvStoreEntry, KvStoreGetOptions, KvStoreQuery,
    KvStoreRemoveOptions, KvStoreSetOptions, KvStoreToken, WalletProtocol,
};

#[cfg(feature = "network")]
pub use global_kvstore::{GlobalKvStore, KeyLocks};
#[cfg(feature = "network")]
pub use local_kvstore::{LocalKvStore, LocalKvStoreConfig};
