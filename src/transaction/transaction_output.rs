//! Bitcoin transaction output type.

use std::io::{Read, Write};

use crate::script::locking_script::LockingScript;
use crate::transaction::error::TransactionError;
use crate::transaction::{read_u64_le, read_varint, write_u64_le, write_varint};

/// A single output in a Bitcoin transaction.
#[derive(Debug, Clone)]
pub struct TransactionOutput {
    /// The value in satoshis (None for outputs not yet assigned a value).
    pub satoshis: Option<u64>,
    /// The locking script (scriptPubKey).
    pub locking_script: LockingScript,
    /// Whether this output is a change output (not serialized).
    pub change: bool,
}

impl Default for TransactionOutput {
    fn default() -> Self {
        Self {
            satoshis: None,
            locking_script: LockingScript::from_binary(&[]),
            change: false,
        }
    }
}

impl TransactionOutput {
    /// Deserialize a transaction output from binary wire format.
    ///
    /// Wire format: satoshis(8 LE) + varint(script_len) + script
    pub fn from_binary(reader: &mut impl Read) -> Result<Self, TransactionError> {
        let satoshis = read_u64_le(reader)?;
        let script_len = read_varint(reader)? as usize;
        let mut script_bytes = vec![0u8; script_len];
        if script_len > 0 {
            reader.read_exact(&mut script_bytes)?;
        }
        let locking_script = LockingScript::from_binary(&script_bytes);

        Ok(TransactionOutput {
            satoshis: Some(satoshis),
            locking_script,
            change: false,
        })
    }

    /// Serialize a transaction output to binary wire format.
    pub fn to_binary(&self, writer: &mut impl Write) -> Result<(), TransactionError> {
        // Write satoshis (default 0 if None)
        write_u64_le(writer, self.satoshis.unwrap_or(0))?;

        // Write script
        let script_bin = self.locking_script.to_binary();
        write_varint(writer, script_bin.len() as u64)?;
        writer.write_all(&script_bin)?;

        Ok(())
    }
}
