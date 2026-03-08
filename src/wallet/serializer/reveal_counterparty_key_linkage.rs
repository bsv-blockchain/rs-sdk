//! RevealCounterpartyKeyLinkage args/result serialization.

use super::*;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::{
    RevealCounterpartyKeyLinkageArgs, RevealCounterpartyKeyLinkageResult,
};

pub fn serialize_reveal_counterparty_key_linkage_args(
    args: &RevealCounterpartyKeyLinkageArgs,
) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| {
        // Privileged params
        write_privileged_params(
            w,
            args.privileged,
            &args.privileged_reason.clone().unwrap_or_default(),
        )?;
        // Counterparty public key
        write_public_key(w, &args.counterparty)?;
        // Verifier public key
        write_public_key(w, &args.verifier)
    })
}

pub fn deserialize_reveal_counterparty_key_linkage_args(
    data: &[u8],
) -> Result<RevealCounterpartyKeyLinkageArgs, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let (privileged, privileged_reason) = read_privileged_params(&mut r)?;
    let counterparty = read_public_key(&mut r)?;
    let verifier = read_public_key(&mut r)?;
    Ok(RevealCounterpartyKeyLinkageArgs {
        counterparty,
        verifier,
        privileged,
        privileged_reason: if privileged_reason.is_empty() {
            None
        } else {
            Some(privileged_reason)
        },
    })
}

pub fn serialize_reveal_counterparty_key_linkage_result(
    result: &RevealCounterpartyKeyLinkageResult,
) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| {
        write_public_key(w, &result.prover)?;
        write_public_key(w, &result.verifier)?;
        write_public_key(w, &result.counterparty)?;
        write_string(w, &result.revelation_time)?;
        write_bytes(w, &result.encrypted_linkage)?;
        write_bytes(w, &result.encrypted_linkage_proof)
    })
}

pub fn deserialize_reveal_counterparty_key_linkage_result(
    data: &[u8],
) -> Result<RevealCounterpartyKeyLinkageResult, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let prover = read_public_key(&mut r)?;
    let verifier = read_public_key(&mut r)?;
    let counterparty = read_public_key(&mut r)?;
    let revelation_time = read_string(&mut r)?;
    let encrypted_linkage = read_bytes(&mut r)?;
    let encrypted_linkage_proof = read_bytes(&mut r)?;
    Ok(RevealCounterpartyKeyLinkageResult {
        prover,
        counterparty,
        verifier,
        revelation_time,
        encrypted_linkage,
        encrypted_linkage_proof,
    })
}
