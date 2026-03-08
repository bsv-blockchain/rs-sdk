//! VerifyHmac args/result serialization.

use super::*;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::{VerifyHmacArgs, VerifyHmacResult};

pub fn serialize_verify_hmac_args(args: &VerifyHmacArgs) -> Result<Vec<u8>, WalletError> {
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
        // HMAC is fixed 32 bytes
        write_raw_bytes(w, &args.hmac)?;
        // Data is length-prefixed
        write_bytes(w, &args.data)?;
        write_optional_bool(w, args.seek_permission)
    })
}

pub fn deserialize_verify_hmac_args(data: &[u8]) -> Result<VerifyHmacArgs, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let params = read_key_related_params(&mut r)?;
    let hmac = read_raw_bytes(&mut r, 32)?;
    let hmac_data = read_bytes(&mut r)?;
    let seek_permission = read_optional_bool(&mut r)?;
    Ok(VerifyHmacArgs {
        protocol_id: params.protocol,
        key_id: params.key_id,
        counterparty: params.counterparty,
        privileged: params.privileged.unwrap_or(false),
        privileged_reason: if params.privileged_reason.is_empty() {
            None
        } else {
            Some(params.privileged_reason)
        },
        hmac,
        data: hmac_data,
        seek_permission,
    })
}

pub fn serialize_verify_hmac_result(_result: &VerifyHmacResult) -> Result<Vec<u8>, WalletError> {
    Ok(Vec::new())
}

pub fn deserialize_verify_hmac_result(_data: &[u8]) -> Result<VerifyHmacResult, WalletError> {
    Ok(VerifyHmacResult { valid: true })
}
