//! Shared DiscoverCertificatesResult serialization.
//!
//! Used by both DiscoverByIdentityKey and DiscoverByAttributes results.

use super::certificate_ser::{deserialize_identity_certificate, serialize_identity_certificate};
use super::*;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::*;

pub fn serialize_discover_certificates_result(
    result: &DiscoverCertificatesResult,
) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| {
        write_varint(w, result.total_certificates as u64)?;
        for cert in &result.certificates {
            let cert_bytes = serialize_identity_certificate(cert)?;
            write_raw_bytes(w, &cert_bytes)?;
        }
        Ok(())
    })
}

pub fn deserialize_discover_certificates_result(
    data: &[u8],
) -> Result<DiscoverCertificatesResult, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let total_certificates = read_varint(&mut r)? as u32;
    let mut certificates = Vec::with_capacity(total_certificates as usize);
    for _ in 0..total_certificates {
        let cert = deserialize_identity_certificate(&mut r)?;
        certificates.push(cert);
    }
    Ok(DiscoverCertificatesResult {
        total_certificates,
        certificates,
    })
}
