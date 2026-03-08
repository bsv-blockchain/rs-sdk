//! IsAuthenticated / WaitForAuthentication result serialization.

use super::*;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::AuthenticatedResult;

pub fn serialize_is_authenticated_result(
    result: &AuthenticatedResult,
) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| write_byte(w, if result.authenticated { 1 } else { 0 }))
}

pub fn deserialize_is_authenticated_result(
    data: &[u8],
) -> Result<AuthenticatedResult, WalletError> {
    if data.len() != 1 {
        return Err(WalletError::Internal(
            "invalid data length for authenticated result".to_string(),
        ));
    }
    Ok(AuthenticatedResult {
        authenticated: data[0] == 1,
    })
}

pub fn serialize_wait_authenticated_result(
    _result: &AuthenticatedResult,
) -> Result<Vec<u8>, WalletError> {
    Ok(Vec::new())
}

pub fn deserialize_wait_authenticated_result(
    _data: &[u8],
) -> Result<AuthenticatedResult, WalletError> {
    Ok(AuthenticatedResult {
        authenticated: true,
    })
}
