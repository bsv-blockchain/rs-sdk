//! Encrypt args/result serialization.

use super::*;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::{EncryptArgs, EncryptResult};

pub fn serialize_encrypt_args(args: &EncryptArgs) -> Result<Vec<u8>, WalletError> {
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
        write_varint(w, args.plaintext.len() as u64)?;
        write_raw_bytes(w, &args.plaintext)?;
        write_optional_bool(w, args.seek_permission)
    })
}

pub fn deserialize_encrypt_args(data: &[u8]) -> Result<EncryptArgs, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let params = read_key_related_params(&mut r)?;
    let plaintext_len = read_varint(&mut r)?;
    let plaintext = read_raw_bytes(&mut r, plaintext_len as usize)?;
    let seek_permission = read_optional_bool(&mut r)?;
    Ok(EncryptArgs {
        protocol_id: params.protocol,
        key_id: params.key_id,
        counterparty: params.counterparty,
        privileged: params.privileged.unwrap_or(false),
        privileged_reason: if params.privileged_reason.is_empty() {
            None
        } else {
            Some(params.privileged_reason)
        },
        plaintext,
        seek_permission,
    })
}

pub fn serialize_encrypt_result(result: &EncryptResult) -> Result<Vec<u8>, WalletError> {
    Ok(result.ciphertext.clone())
}

pub fn deserialize_encrypt_result(data: &[u8]) -> Result<EncryptResult, WalletError> {
    Ok(EncryptResult {
        ciphertext: data.to_vec(),
    })
}
