//! Transaction signature type with sighash flag support.
//!
//! TransactionSignature wraps an ECDSA Signature with a sighash scope byte.
//! It provides DER encoding that includes the trailing sighash type byte,
//! matching the Bitcoin checksig format.
//!
//! Phase 3 TODOs: format() and formatOTDA() methods require Script and
//! Transaction types that are not yet available.

use crate::primitives::big_number::BigNumber;
use crate::primitives::error::PrimitivesError;
use crate::primitives::signature::Signature;

/// Sighash type: sign all inputs and outputs.
pub const SIGHASH_ALL: u32 = 0x01;

/// Sighash type: sign all inputs, no outputs.
pub const SIGHASH_NONE: u32 = 0x02;

/// Sighash type: sign all inputs, only the output at the same index.
pub const SIGHASH_SINGLE: u32 = 0x03;

/// Sighash flag: only sign the current input.
pub const SIGHASH_ANYONECANPAY: u32 = 0x80;

/// Sighash flag: BSV fork ID (required for post-fork transactions).
pub const SIGHASH_FORKID: u32 = 0x40;

/// A transaction signature combining an ECDSA signature with a sighash type.
///
/// In Bitcoin transactions, signatures include a trailing sighash byte that
/// indicates which parts of the transaction are covered by the signature.
/// This type wraps a Signature with that sighash scope.
pub struct TransactionSignature {
    /// The underlying ECDSA signature.
    sig: Signature,
    /// The sighash flags (e.g., SIGHASH_ALL | SIGHASH_FORKID).
    scope: u32,
}

impl TransactionSignature {
    /// Create a new TransactionSignature from a Signature and sighash scope.
    pub fn new(sig: Signature, scope: u32) -> Self {
        TransactionSignature { sig, scope }
    }

    /// Parse from checksig format bytes (DER + trailing sighash byte).
    ///
    /// If the input is empty, creates a "blank" signature with r=1, s=1
    /// and scope=SIGHASH_ALL (matching TS SDK behavior).
    ///
    /// The last byte is the sighash type. The remaining bytes are
    /// the DER-encoded ECDSA signature. If `force_low_s` is true,
    /// the signature is normalized to low-S form.
    pub fn from_checksig_format(bytes: &[u8], force_low_s: bool) -> Result<Self, PrimitivesError> {
        if bytes.is_empty() {
            // Blank signature, matching TS SDK fromChecksigFormat behavior
            let r = BigNumber::one();
            let s = BigNumber::one();
            return Ok(TransactionSignature {
                sig: Signature::new(r, s),
                scope: SIGHASH_ALL,
            });
        }

        let scope = bytes[bytes.len() - 1] as u32;
        let der_bytes = &bytes[..bytes.len() - 1];
        let sig = Signature::from_der(der_bytes)?;

        let sig = if force_low_s && !sig.has_low_s() {
            sig.to_low_s()
        } else {
            sig
        };

        Ok(TransactionSignature { sig, scope })
    }

    /// Serialize to checksig format: DER bytes + sighash byte appended.
    pub fn to_checksig_format(&self) -> Vec<u8> {
        let mut result = self.sig.to_der();
        result.push(self.scope as u8);
        result
    }

    /// Get the sighash scope flags.
    pub fn scope(&self) -> u32 {
        self.scope
    }

    /// Get a reference to the inner Signature.
    pub fn signature(&self) -> &Signature {
        &self.sig
    }

    /// Check if the inner signature has low-S value.
    pub fn has_low_s(&self) -> bool {
        self.sig.has_low_s()
    }

    /// Check if the FORKID flag is set in the scope.
    pub fn has_forkid(&self) -> bool {
        (self.scope & SIGHASH_FORKID) != 0
    }

    // TODO (Phase 3): format() method - requires Script type
    // TODO (Phase 3): formatOTDA() method - requires TransactionInput/TransactionOutput types
    // TODO (Phase 3): formatBip143() method - requires Script and Transaction types
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sighash_all_value() {
        assert_eq!(SIGHASH_ALL, 0x01);
    }

    #[test]
    fn test_sighash_none_value() {
        assert_eq!(SIGHASH_NONE, 0x02);
    }

    #[test]
    fn test_sighash_single_value() {
        assert_eq!(SIGHASH_SINGLE, 0x03);
    }

    #[test]
    fn test_sighash_anyonecanpay_value() {
        assert_eq!(SIGHASH_ANYONECANPAY, 0x80);
    }

    #[test]
    fn test_sighash_forkid_value() {
        assert_eq!(SIGHASH_FORKID, 0x40);
    }

    #[test]
    fn test_new_stores_scope() {
        let sig = Signature::new(BigNumber::one(), BigNumber::one());
        let ts = TransactionSignature::new(sig, SIGHASH_ALL | SIGHASH_FORKID);
        assert_eq!(ts.scope(), SIGHASH_ALL | SIGHASH_FORKID);
    }

    #[test]
    fn test_new_preserves_signature() {
        let r =
            BigNumber::from_hex("4e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41")
                .unwrap();
        let s =
            BigNumber::from_hex("181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09")
                .unwrap();
        let sig = Signature::new(r.clone(), s.clone());
        let ts = TransactionSignature::new(sig, SIGHASH_ALL);
        assert_eq!(ts.signature().r().cmp(&r), 0);
        assert_eq!(ts.signature().s().cmp(&s), 0);
    }

    #[test]
    fn test_to_checksig_format_appends_scope() {
        let sig = Signature::new(BigNumber::one(), BigNumber::one());
        let scope = SIGHASH_ALL | SIGHASH_FORKID;
        let ts = TransactionSignature::new(sig, scope);
        let bytes = ts.to_checksig_format();
        // Last byte should be the scope
        assert_eq!(*bytes.last().unwrap(), scope as u8);
        // Preceding bytes should be valid DER
        let der_bytes = &bytes[..bytes.len() - 1];
        let recovered = Signature::from_der(der_bytes).unwrap();
        assert_eq!(recovered.r().cmp(&BigNumber::one()), 0);
    }

    #[test]
    fn test_from_checksig_format_parses_der_and_scope() {
        // Build a checksig-format byte array: DER(r=1,s=1) + sighash byte
        let sig = Signature::new(BigNumber::one(), BigNumber::one());
        let mut checksig_bytes = sig.to_der();
        let scope = SIGHASH_ALL | SIGHASH_FORKID;
        checksig_bytes.push(scope as u8);

        let ts = TransactionSignature::from_checksig_format(&checksig_bytes, false).unwrap();
        assert_eq!(ts.scope(), scope);
        assert_eq!(ts.signature().r().cmp(&BigNumber::one()), 0);
        assert_eq!(ts.signature().s().cmp(&BigNumber::one()), 0);
    }

    #[test]
    fn test_from_checksig_format_with_real_sig() {
        let r =
            BigNumber::from_hex("4e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41")
                .unwrap();
        let s =
            BigNumber::from_hex("181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09")
                .unwrap();
        let sig = Signature::new(r, s);
        let scope = SIGHASH_ALL | SIGHASH_FORKID;
        let mut checksig_bytes = sig.to_der();
        checksig_bytes.push(scope as u8);

        let ts = TransactionSignature::from_checksig_format(&checksig_bytes, false).unwrap();
        assert_eq!(ts.scope(), scope);
        assert_eq!(
            ts.signature().r().to_hex(),
            "4e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41"
        );
    }

    #[test]
    fn test_checksig_format_round_trip() {
        let r =
            BigNumber::from_hex("813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365")
                .unwrap();
        let s =
            BigNumber::from_hex("6ff18a52dcc0336f7af62400a6dd9b810732baf1ff758000d6f613a556eb31ba")
                .unwrap();
        let sig = Signature::new(r.clone(), s.clone());
        let scope = SIGHASH_ALL | SIGHASH_FORKID;
        let ts = TransactionSignature::new(sig, scope);
        let bytes = ts.to_checksig_format();
        let recovered = TransactionSignature::from_checksig_format(&bytes, false).unwrap();
        assert_eq!(recovered.scope(), scope);
        assert_eq!(recovered.signature().r().cmp(&r), 0);
        assert_eq!(recovered.signature().s().cmp(&s), 0);
    }

    #[test]
    fn test_has_low_s_delegates() {
        let sig = Signature::new(BigNumber::one(), BigNumber::one());
        let ts = TransactionSignature::new(sig, SIGHASH_ALL);
        assert!(ts.has_low_s());
    }

    #[test]
    fn test_has_low_s_high_s() {
        let high_s =
            BigNumber::from_hex("e7eadd137135f821b79f5b5322ed6f6137921779f39c5a19b7b03ce459a92438")
                .unwrap();
        let sig = Signature::new(BigNumber::one(), high_s);
        let ts = TransactionSignature::new(sig, SIGHASH_ALL);
        assert!(!ts.has_low_s());
    }

    #[test]
    fn test_has_forkid_set() {
        let sig = Signature::new(BigNumber::one(), BigNumber::one());
        let ts = TransactionSignature::new(sig, SIGHASH_ALL | SIGHASH_FORKID);
        assert!(ts.has_forkid());
    }

    #[test]
    fn test_has_forkid_not_set() {
        let sig = Signature::new(BigNumber::one(), BigNumber::one());
        let ts = TransactionSignature::new(sig, SIGHASH_ALL);
        assert!(!ts.has_forkid());
    }

    #[test]
    fn test_default_scope_all_forkid() {
        let sig = Signature::new(BigNumber::one(), BigNumber::one());
        let ts = TransactionSignature::new(sig, SIGHASH_ALL | SIGHASH_FORKID);
        assert_eq!(ts.scope(), 0x41);
        assert!(ts.has_forkid());
    }

    #[test]
    fn test_from_checksig_format_force_low_s() {
        let high_s =
            BigNumber::from_hex("e7eadd137135f821b79f5b5322ed6f6137921779f39c5a19b7b03ce459a92438")
                .unwrap();
        let sig = Signature::new(BigNumber::one(), high_s);
        let mut checksig_bytes = sig.to_der();
        checksig_bytes.push(SIGHASH_ALL as u8);

        let ts = TransactionSignature::from_checksig_format(&checksig_bytes, true).unwrap();
        assert!(ts.has_low_s());
    }

    #[test]
    fn test_from_checksig_format_empty_creates_blank() {
        // TS SDK allows empty buf to create a "blank" signature
        let ts = TransactionSignature::from_checksig_format(&[], false).unwrap();
        assert_eq!(ts.scope(), SIGHASH_ALL);
        assert_eq!(ts.signature().r().cmp(&BigNumber::one()), 0);
        assert_eq!(ts.signature().s().cmp(&BigNumber::one()), 0);
    }
}
