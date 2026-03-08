//! GetHeader args/result serialization.

use super::*;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::{GetHeaderArgs, GetHeaderResult};

pub fn serialize_get_header_args(args: &GetHeaderArgs) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| write_varint(w, args.height as u64))
}

pub fn deserialize_get_header_args(data: &[u8]) -> Result<GetHeaderArgs, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let height = read_varint(&mut r)? as u32;
    Ok(GetHeaderArgs { height })
}

pub fn serialize_get_header_result(result: &GetHeaderResult) -> Result<Vec<u8>, WalletError> {
    Ok(result.header.clone())
}

pub fn deserialize_get_header_result(data: &[u8]) -> Result<GetHeaderResult, WalletError> {
    Ok(GetHeaderResult {
        header: data.to_vec(),
    })
}
