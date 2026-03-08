//! AbortAction args/result serialization.

use crate::wallet::error::WalletError;
use crate::wallet::interfaces::{AbortActionArgs, AbortActionResult};

pub fn serialize_abort_action_args(args: &AbortActionArgs) -> Result<Vec<u8>, WalletError> {
    Ok(args.reference.clone())
}

pub fn deserialize_abort_action_args(data: &[u8]) -> Result<AbortActionArgs, WalletError> {
    Ok(AbortActionArgs {
        reference: data.to_vec(),
    })
}

pub fn serialize_abort_action_result(_result: &AbortActionResult) -> Result<Vec<u8>, WalletError> {
    Ok(Vec::new())
}

pub fn deserialize_abort_action_result(_data: &[u8]) -> Result<AbortActionResult, WalletError> {
    Ok(AbortActionResult { aborted: true })
}
