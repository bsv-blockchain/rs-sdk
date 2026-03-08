//! Registry service module for managing on-chain definitions.
//!
//! Provides RegistryClient for CRUD operations on basket, protocol, and
//! certificate definitions via PushDrop tokens broadcast to overlay topics.

pub mod registry_client;
pub mod types;

pub use registry_client::RegistryClient;
pub use types::{
    BasketDefinitionData, BasketQuery, CertificateDefinitionData, CertificateFieldDescriptor,
    CertificateQuery, DefinitionData, DefinitionType, ProtocolDefinitionData, ProtocolQuery,
    RegistryClientOptions, RegistryRecord, TokenData,
};
