//! BEEF format (BRC-62/95/96) serialization and deserialization.
//!
//! Supports V1, V2, and Atomic BEEF variants for SPV proof packaging.
//! Stub for Task 1 -- full implementation in Task 2.

use std::io::{Cursor, Read, Write};

use crate::primitives::utils::{from_hex, to_hex};
use crate::transaction::beef_tx::BeefTx;
use crate::transaction::error::TransactionError;
use crate::transaction::merkle_path::MerklePath;
use crate::transaction::{read_u32_le, read_varint, write_u32_le, write_varint};

/// BEEF V1 version marker (0x0100BEEF in LE = 4022206465).
pub const BEEF_V1: u32 = 4022206465;
/// BEEF V2 version marker (0x0200BEEF in LE = 4022206466).
pub const BEEF_V2: u32 = 4022206466;
/// Atomic BEEF prefix (0x01010101).
pub const ATOMIC_BEEF: u32 = 0x01010101;

/// A BEEF (Background Evaluation Extended Format) container.
///
/// Contains a set of BUMPs (Merkle paths) and transactions that together
/// form a validity proof chain for SPV verification.
#[derive(Debug, Clone)]
pub struct Beef {
    /// BEEF version (BEEF_V1 or BEEF_V2).
    pub version: u32,
    /// Merkle paths (BUMPs) proving transaction inclusion in blocks.
    pub bumps: Vec<MerklePath>,
    /// Transactions with BEEF metadata.
    pub txs: Vec<BeefTx>,
    /// For Atomic BEEF: the txid of the proven transaction.
    pub atomic_txid: Option<String>,
}

impl Beef {
    /// Create a new empty Beef with the given version.
    pub fn new(version: u32) -> Self {
        Beef {
            version,
            bumps: Vec::new(),
            txs: Vec::new(),
            atomic_txid: None,
        }
    }

    /// Deserialize a Beef from binary format.
    pub fn from_binary(reader: &mut impl Read) -> Result<Self, TransactionError> {
        let mut version = read_u32_le(reader)?;
        let mut atomic_txid = None;

        if version == ATOMIC_BEEF {
            // Read 32-byte txid (reversed/LE on wire -> BE display hex)
            let mut txid_bytes = [0u8; 32];
            reader.read_exact(&mut txid_bytes)?;
            txid_bytes.reverse();
            atomic_txid = Some(to_hex(&txid_bytes));
            // Read inner BEEF version
            version = read_u32_le(reader)?;
        }

        if version != BEEF_V1 && version != BEEF_V2 {
            return Err(TransactionError::BeefError(format!(
                "Serialized BEEF must start with {} or {} but starts with {}",
                BEEF_V1, BEEF_V2, version
            )));
        }

        let mut beef = Beef::new(version);

        // Read bumps
        let bump_count = read_varint(reader)
            .map_err(|e| TransactionError::InvalidFormat(e.to_string()))?
            as usize;
        for _ in 0..bump_count {
            let bump = MerklePath::from_binary(reader)?;
            beef.bumps.push(bump);
        }

        // Read transactions
        let tx_count = read_varint(reader)
            .map_err(|e| TransactionError::InvalidFormat(e.to_string()))?
            as usize;
        for _ in 0..tx_count {
            let beef_tx = if version == BEEF_V2 {
                BeefTx::from_binary_v2(reader)?
            } else {
                BeefTx::from_binary_v1(reader)?
            };
            beef.txs.push(beef_tx);
        }

        beef.atomic_txid = atomic_txid;

        // Link source transactions: for each input of each tx, if the input's
        // source_txid matches another tx in the BEEF, set source_transaction.
        beef.link_source_transactions();

        Ok(beef)
    }

    /// Serialize this Beef to binary format.
    pub fn to_binary(&self, writer: &mut impl Write) -> Result<(), TransactionError> {
        // Write Atomic BEEF prefix if applicable
        if let Some(ref txid) = self.atomic_txid {
            write_u32_le(writer, ATOMIC_BEEF)?;
            let mut txid_bytes =
                from_hex(txid).map_err(|e| TransactionError::InvalidFormat(e.to_string()))?;
            txid_bytes.reverse(); // BE display -> LE wire
            writer.write_all(&txid_bytes)?;
        }

        write_u32_le(writer, self.version)?;

        // Write bumps
        write_varint(writer, self.bumps.len() as u64)?;
        for bump in &self.bumps {
            bump.to_binary(writer)?;
        }

        // Write transactions
        write_varint(writer, self.txs.len() as u64)?;
        for tx in &self.txs {
            if self.version == BEEF_V2 {
                tx.to_binary_v2(writer)?;
            } else {
                tx.to_binary_v1(writer)?;
            }
        }

        Ok(())
    }

    /// Deserialize a Beef from a hex string.
    pub fn from_hex(hex: &str) -> Result<Self, TransactionError> {
        let bytes = from_hex(hex).map_err(|e| TransactionError::InvalidFormat(e.to_string()))?;
        let mut cursor = Cursor::new(bytes);
        Self::from_binary(&mut cursor)
    }

    /// Serialize this Beef to a hex string.
    pub fn to_hex(&self) -> Result<String, TransactionError> {
        let mut buf = Vec::new();
        self.to_binary(&mut buf)?;
        Ok(to_hex(&buf))
    }

    /// Link source transactions within this BEEF.
    ///
    /// For each transaction input, if its source_txid matches another transaction
    /// in this BEEF, set source_transaction to point to it.
    fn link_source_transactions(&mut self) {
        // Collect txid -> index mapping
        let txid_map: Vec<(String, usize)> = self
            .txs
            .iter()
            .enumerate()
            .map(|(i, btx)| (btx.txid.clone(), i))
            .collect();

        // We need to clone transactions to set source_transaction references
        // because Rust ownership rules prevent borrowing self.txs mutably
        // while also reading from it. We clone the source txs.
        let tx_clones: Vec<Option<crate::transaction::transaction::Transaction>> =
            self.txs.iter().map(|btx| btx.tx.clone()).collect();

        for btx in &mut self.txs {
            if let Some(ref mut tx) = btx.tx {
                for input in &mut tx.inputs {
                    if let Some(ref source_txid) = input.source_txid {
                        if input.source_transaction.is_none() {
                            // Find matching tx in BEEF
                            if let Some((_, idx)) =
                                txid_map.iter().find(|(tid, _)| tid == source_txid)
                            {
                                if let Some(ref source_tx) = tx_clones[*idx] {
                                    input.source_transaction = Some(Box::new(source_tx.clone()));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct BeefVector {
        name: String,
        hex: String,
        version: u32,
        bump_count: usize,
        tx_count: usize,
        #[serde(default)]
        txid: Option<String>,
    }

    fn load_test_vectors() -> Vec<BeefVector> {
        let json = include_str!("../../test-vectors/beef_valid.json");
        serde_json::from_str(json).expect("failed to parse beef_valid.json")
    }

    #[test]
    fn test_beef_v1_round_trip() {
        let vectors = load_test_vectors();
        for v in vectors.iter().filter(|v| v.version == 1) {
            let beef = Beef::from_hex(&v.hex)
                .unwrap_or_else(|e| panic!("failed to parse '{}': {}", v.name, e));
            assert_eq!(
                beef.bumps.len(),
                v.bump_count,
                "bump count mismatch for '{}'",
                v.name
            );
            assert_eq!(
                beef.txs.len(),
                v.tx_count,
                "tx count mismatch for '{}'",
                v.name
            );

            let result_hex = beef
                .to_hex()
                .unwrap_or_else(|e| panic!("failed to serialize '{}': {}", v.name, e));
            assert_eq!(result_hex, v.hex, "round-trip failed for '{}'", v.name);
        }
    }

    #[test]
    fn test_beef_tx_count() {
        let vectors = load_test_vectors();
        for v in &vectors {
            let beef = Beef::from_hex(&v.hex)
                .unwrap_or_else(|e| panic!("failed to parse '{}': {}", v.name, e));
            assert_eq!(
                beef.bumps.len(),
                v.bump_count,
                "bump count mismatch for '{}'",
                v.name
            );
            assert_eq!(
                beef.txs.len(),
                v.tx_count,
                "tx count mismatch for '{}'",
                v.name
            );

            // Verify txid if provided
            if let Some(ref expected_txid) = v.txid {
                let last_tx = &beef.txs[beef.txs.len() - 1];
                assert_eq!(
                    &last_tx.txid, expected_txid,
                    "txid mismatch for '{}'",
                    v.name
                );
            }
        }
    }
}
