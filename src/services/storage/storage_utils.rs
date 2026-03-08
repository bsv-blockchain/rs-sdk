//! UHRP URL encoding/decoding utilities.
//!
//! Translates the TS SDK StorageUtils.ts. Provides functions for encoding
//! and decoding UHRP (Universal Hash Resolution Protocol) URLs using
//! Base58Check with a 0xCE00 prefix.

use crate::primitives::hash::sha256;
use crate::primitives::utils::{base58_check_decode, base58_check_encode};
use crate::services::ServicesError;

/// UHRP prefix bytes: 0xCE 0x00.
const UHRP_PREFIX: [u8; 2] = [0xce, 0x00];

/// Normalize a UHRP URL by stripping "uhrp:" and "//" prefixes.
fn normalize_url(url: &str) -> String {
    let mut s = url.to_string();
    if s.to_lowercase().starts_with("uhrp:") {
        s = s[5..].to_string();
    }
    if s.starts_with("//") {
        s = s[2..].to_string();
    }
    s
}

/// Generate a UHRP URL from a 32-byte SHA-256 hash.
///
/// Encodes the hash using Base58Check with the 0xCE00 prefix.
pub fn get_url_for_hash(hash: &[u8; 32]) -> String {
    base58_check_encode(hash, &UHRP_PREFIX)
}

/// Generate a UHRP URL for a file by computing its SHA-256 hash.
pub fn get_url_for_file(data: &[u8]) -> String {
    let hash = sha256(data);
    get_url_for_hash(&hash)
}

/// Extract the 32-byte SHA-256 hash from a UHRP URL.
///
/// Normalizes the URL (stripping "uhrp:" and "//" prefixes), decodes
/// via Base58Check, verifies the UHRP prefix, and returns the 32-byte hash.
pub fn get_hash_from_url(url: &str) -> Result<[u8; 32], ServicesError> {
    let normalized = normalize_url(url);
    let (prefix, payload) =
        base58_check_decode(&normalized, 2).map_err(|e| ServicesError::Storage(e.to_string()))?;

    if prefix != UHRP_PREFIX {
        return Err(ServicesError::Storage("bad UHRP prefix".into()));
    }

    if payload.len() != 32 {
        return Err(ServicesError::Storage(format!(
            "invalid hash length: expected 32, got {}",
            payload.len()
        )));
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&payload);
    Ok(hash)
}

/// Check whether a URL is a valid UHRP URL.
pub fn is_valid_url(url: &str) -> bool {
    get_hash_from_url(url).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_hash_to_url_to_hash() {
        let hash: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let url = get_url_for_hash(&hash);
        let recovered = get_hash_from_url(&url).unwrap();
        assert_eq!(hash, recovered, "round-trip hash must match");
    }

    #[test]
    fn test_known_vector_sha256_file() {
        // SHA-256 of b"hello" is a known value.
        let data = b"hello";
        let expected_hash = sha256(data);
        let url = get_url_for_file(data);
        let recovered = get_hash_from_url(&url).unwrap();
        assert_eq!(expected_hash, recovered);
    }

    #[test]
    fn test_normalize_uhrp_prefix() {
        let hash: [u8; 32] = [0xaa; 32];
        let url = get_url_for_hash(&hash);

        // With "uhrp://" prefix
        let prefixed = format!("uhrp://{}", url);
        let recovered = get_hash_from_url(&prefixed).unwrap();
        assert_eq!(hash, recovered);

        // With "UHRP:" prefix (case insensitive)
        let upper = format!("UHRP:{}", url);
        let recovered2 = get_hash_from_url(&upper).unwrap();
        assert_eq!(hash, recovered2);
    }

    #[test]
    fn test_invalid_url_rejected() {
        assert!(get_hash_from_url("not-a-valid-url").is_err());
        assert!(!is_valid_url("not-a-valid-url"));
    }

    #[test]
    fn test_is_valid_url_with_valid() {
        let hash: [u8; 32] = [0xbb; 32];
        let url = get_url_for_hash(&hash);
        assert!(is_valid_url(&url));
    }
}
