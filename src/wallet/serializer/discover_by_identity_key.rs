//! DiscoverByIdentityKey args serialization.
//! Result uses the shared DiscoverCertificatesResult (see discover_certificates_result).

use super::*;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::*;

pub fn serialize_discover_by_identity_key_args(
    args: &DiscoverByIdentityKeyArgs,
) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| {
        // Identity key (33 bytes)
        write_public_key(w, &args.identity_key)?;
        // Limit, offset, seek permission
        write_optional_uint32(w, args.limit)?;
        write_optional_uint32(w, args.offset)?;
        write_optional_bool(w, args.seek_permission)
    })
}

pub fn deserialize_discover_by_identity_key_args(
    data: &[u8],
) -> Result<DiscoverByIdentityKeyArgs, WalletError> {
    let mut r = std::io::Cursor::new(data);
    let identity_key = read_public_key(&mut r)?;
    let limit = read_optional_uint32(&mut r)?;
    let offset = read_optional_uint32(&mut r)?;
    let seek_permission = read_optional_bool(&mut r)?;
    Ok(DiscoverByIdentityKeyArgs {
        identity_key,
        limit,
        offset,
        seek_permission,
    })
}
