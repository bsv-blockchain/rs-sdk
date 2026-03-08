//! RelinquishOutput args/result serialization.

use super::*;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::{RelinquishOutputArgs, RelinquishOutputResult};

pub fn serialize_relinquish_output_args(
    args: &RelinquishOutputArgs,
) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| {
        write_string(w, &args.basket)?;
        write_outpoint(w, &args.output)
    })
}

pub fn deserialize_relinquish_output_args(
    data: &[u8],
) -> Result<RelinquishOutputArgs, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let basket = read_string(&mut r)?;
    let output = read_outpoint(&mut r)?;
    Ok(RelinquishOutputArgs { basket, output })
}

pub fn serialize_relinquish_output_result(
    _result: &RelinquishOutputResult,
) -> Result<Vec<u8>, WalletError> {
    Ok(Vec::new())
}

pub fn deserialize_relinquish_output_result(
    _data: &[u8],
) -> Result<RelinquishOutputResult, WalletError> {
    Ok(RelinquishOutputResult { relinquished: true })
}
