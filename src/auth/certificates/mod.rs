//! Certificate hierarchy for auth module.
//!
//! Provides AuthCertificate (sign/verify/encrypt/decrypt), VerifiableCertificate
//! (selective field revelation), MasterCertificate (master keyring management),
//! and CompoundMerklePathCertificate (certificate + merkle proof).

pub mod certificate;
pub mod compound;
pub mod master;
pub mod verifiable;

pub use certificate::AuthCertificate;
pub use compound::CompoundMerklePathCertificate;
pub use master::MasterCertificate;
pub use verifiable::VerifiableCertificate;
