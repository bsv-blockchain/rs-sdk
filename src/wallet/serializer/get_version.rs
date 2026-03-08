//! GetVersion result serialization.

use crate::wallet::error::WalletError;
use crate::wallet::interfaces::GetVersionResult;

pub fn serialize_get_version_result(result: &GetVersionResult) -> Result<Vec<u8>, WalletError> {
    Ok(result.version.as_bytes().to_vec())
}

pub fn deserialize_get_version_result(data: &[u8]) -> Result<GetVersionResult, WalletError> {
    Ok(GetVersionResult {
        version: String::from_utf8(data.to_vec())
            .map_err(|e| WalletError::Internal(e.to_string()))?,
    })
}
