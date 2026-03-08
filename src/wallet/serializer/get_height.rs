//! GetHeight result serialization.

use super::*;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::GetHeightResult;

pub fn serialize_get_height_result(result: &GetHeightResult) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| write_varint(w, result.height as u64))
}

pub fn deserialize_get_height_result(data: &[u8]) -> Result<GetHeightResult, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let height = read_varint(&mut r)? as u32;
    Ok(GetHeightResult { height })
}
