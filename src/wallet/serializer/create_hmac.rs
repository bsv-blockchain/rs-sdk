//! CreateHmac args/result serialization.

use super::*;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::{CreateHmacArgs, CreateHmacResult};

pub fn serialize_create_hmac_args(args: &CreateHmacArgs) -> Result<Vec<u8>, WalletError> {
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
        write_varint(w, args.data.len() as u64)?;
        write_raw_bytes(w, &args.data)?;
        write_optional_bool(w, args.seek_permission)
    })
}

pub fn deserialize_create_hmac_args(data: &[u8]) -> Result<CreateHmacArgs, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let params = read_key_related_params(&mut r)?;
    let data_len = read_varint(&mut r)?;
    let hmac_data = read_raw_bytes(&mut r, data_len as usize)?;
    let seek_permission = read_optional_bool(&mut r)?;
    Ok(CreateHmacArgs {
        protocol_id: params.protocol,
        key_id: params.key_id,
        counterparty: params.counterparty,
        privileged: params.privileged.unwrap_or(false),
        privileged_reason: if params.privileged_reason.is_empty() {
            None
        } else {
            Some(params.privileged_reason)
        },
        data: hmac_data,
        seek_permission,
    })
}

pub fn serialize_create_hmac_result(result: &CreateHmacResult) -> Result<Vec<u8>, WalletError> {
    Ok(result.hmac.clone())
}

pub fn deserialize_create_hmac_result(data: &[u8]) -> Result<CreateHmacResult, WalletError> {
    Ok(CreateHmacResult {
        hmac: data.to_vec(),
    })
}
