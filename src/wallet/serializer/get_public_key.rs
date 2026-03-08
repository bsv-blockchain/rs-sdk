//! GetPublicKey args/result serialization.

use super::*;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::{GetPublicKeyArgs, GetPublicKeyResult};

pub fn serialize_get_public_key_args(args: &GetPublicKeyArgs) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| {
        // Identity key flag
        write_byte(w, if args.identity_key { 1 } else { 0 })?;

        if !args.identity_key {
            // Key-related params
            let protocol = args
                .protocol_id
                .clone()
                .unwrap_or(crate::wallet::types::Protocol {
                    security_level: 0,
                    protocol: String::new(),
                });
            let counterparty =
                args.counterparty
                    .clone()
                    .unwrap_or(crate::wallet::types::Counterparty {
                        counterparty_type: crate::wallet::types::CounterpartyType::Uninitialized,
                        public_key: None,
                    });
            write_key_related_params(
                w,
                &KeyRelatedParams {
                    protocol,
                    key_id: args.key_id.clone().unwrap_or_default(),
                    counterparty,
                    privileged: Some(args.privileged),
                    privileged_reason: args.privileged_reason.clone().unwrap_or_default(),
                },
            )?;
            // forSelf flag
            write_optional_bool(w, args.for_self)?;
        } else {
            // Identity key case: privileged params
            write_privileged_params(
                w,
                Some(args.privileged),
                &args.privileged_reason.clone().unwrap_or_default(),
            )?;
        }

        // seekPermission
        write_optional_bool(w, args.seek_permission)
    })
}

pub fn deserialize_get_public_key_args(data: &[u8]) -> Result<GetPublicKeyArgs, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let identity_key = read_byte(&mut r)? == 1;

    let (protocol_id, key_id, counterparty, privileged, privileged_reason, for_self) =
        if !identity_key {
            let params = read_key_related_params(&mut r)?;
            let for_self = read_optional_bool(&mut r)?;
            (
                Some(params.protocol),
                Some(params.key_id),
                Some(params.counterparty),
                params.privileged.unwrap_or(false),
                if params.privileged_reason.is_empty() {
                    None
                } else {
                    Some(params.privileged_reason)
                },
                for_self,
            )
        } else {
            let (priv_opt, reason) = read_privileged_params(&mut r)?;
            (
                None,
                None,
                None,
                priv_opt.unwrap_or(false),
                if reason.is_empty() {
                    None
                } else {
                    Some(reason)
                },
                None,
            )
        };

    let seek_permission = read_optional_bool(&mut r)?;

    Ok(GetPublicKeyArgs {
        identity_key,
        protocol_id,
        key_id,
        counterparty,
        privileged,
        privileged_reason,
        for_self,
        seek_permission,
    })
}

pub fn serialize_get_public_key_result(
    result: &GetPublicKeyResult,
) -> Result<Vec<u8>, WalletError> {
    Ok(result.public_key.to_der())
}

pub fn deserialize_get_public_key_result(data: &[u8]) -> Result<GetPublicKeyResult, WalletError> {
    let pk = crate::primitives::public_key::PublicKey::from_der_bytes(data)
        .map_err(|e| WalletError::Internal(e.to_string()))?;
    Ok(GetPublicKeyResult { public_key: pk })
}
