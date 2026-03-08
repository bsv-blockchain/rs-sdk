//! Identity service module for resolving and managing identities.
//!
//! Provides IdentityClient for identity resolution via the overlay network
//! and ContactsManager for cached contact management with wallet-backed
//! encrypted storage.

pub mod contacts_manager;
pub mod identity_client;
pub mod types;

pub use contacts_manager::ContactsManager;
pub use identity_client::IdentityClient;
pub use types::{
    contact_protocol, default_identity, Contact, DisplayableIdentity, IdentityClientOptions,
    KnownIdentityTypes,
};
