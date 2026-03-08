//! Decrypt args/result serialization.

use super::*;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::{DecryptArgs, DecryptResult};

pub fn serialize_decrypt_args(args: &DecryptArgs) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| {
        write_key_related_params(
            w,
            &KeyRelatedParams {
                protocol: args.protocol_id.clone(),
                key_id: args.key_id.clone(),
                counterparty: args.counterparty.clone(),
                privileged: Some(args.privileged),
                privileged_reason: args.privileged_reason.clone().unwrap_or_default(),
            },
        )?;
        write_varint(w, args.ciphertext.len() as u64)?;
        write_raw_bytes(w, &args.ciphertext)?;
        write_optional_bool(w, args.seek_permission)
    })
}

pub fn deserialize_decrypt_args(data: &[u8]) -> Result<DecryptArgs, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let params = read_key_related_params(&mut r)?;
    let ct_len = read_varint(&mut r)?;
    let ciphertext = read_raw_bytes(&mut r, ct_len as usize)?;
    let seek_permission = read_optional_bool(&mut r)?;
    Ok(DecryptArgs {
        protocol_id: params.protocol,
        key_id: params.key_id,
        counterparty: params.counterparty,
        privileged: params.privileged.unwrap_or(false),
        privileged_reason: if params.privileged_reason.is_empty() {
            None
        } else {
            Some(params.privileged_reason)
        },
        ciphertext,
        seek_permission,
    })
}

pub fn serialize_decrypt_result(result: &DecryptResult) -> Result<Vec<u8>, WalletError> {
    Ok(result.plaintext.clone())
}

pub fn deserialize_decrypt_result(data: &[u8]) -> Result<DecryptResult, WalletError> {
    Ok(DecryptResult {
        plaintext: data.to_vec(),
    })
}
