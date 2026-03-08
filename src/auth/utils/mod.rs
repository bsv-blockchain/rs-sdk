//! Auth utility functions.

pub mod certificates;
pub mod nonce;

pub use certificates::{
    get_certificate_field_encryption_key_id, get_master_field_encryption_key_id,
    get_verifiable_certificates, validate_certificates,
};
pub use nonce::{create_nonce, verify_nonce};
