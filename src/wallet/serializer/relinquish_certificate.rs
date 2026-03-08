//! RelinquishCertificate args/result serialization.

use super::*;
use crate::wallet::error::WalletError;
use crate::wallet::interfaces::*;

pub fn serialize_relinquish_certificate_args(
    args: &RelinquishCertificateArgs,
) -> Result<Vec<u8>, WalletError> {
    serialize_to_vec(|w| {
        // Type (32 bytes)
        write_raw_bytes(w, args.cert_type.bytes())?;
        // Serial number (32 bytes)
        write_raw_bytes(w, &args.serial_number.0)?;
        // Certifier (33 bytes)
        write_public_key(w, &args.certifier)
    })
}

pub fn deserialize_relinquish_certificate_args(
    data: &[u8],
) -> Result<RelinquishCertificateArgs, WalletError> {
    let mut r = std::io::Cursor::new(data);
    // Type (32 bytes)
    let mut type_bytes = [0u8; 32];
    let tb = read_raw_bytes(&mut r, SIZE_TYPE)?;
    type_bytes.copy_from_slice(&tb);
    let cert_type = CertificateType(type_bytes);
    // Serial number (32 bytes)
    let mut sn_bytes = [0u8; 32];
    let sb = read_raw_bytes(&mut r, SIZE_SERIAL)?;
    sn_bytes.copy_from_slice(&sb);
    let serial_number = SerialNumber(sn_bytes);
    // Certifier (33 bytes)
    let certifier = read_public_key(&mut r)?;
    Ok(RelinquishCertificateArgs {
        cert_type,
        serial_number,
        certifier,
    })
}

pub fn serialize_relinquish_certificate_result(
    _result: &RelinquishCertificateResult,
) -> Result<Vec<u8>, WalletError> {
    Ok(Vec::new())
}

pub fn deserialize_relinquish_certificate_result(
    _data: &[u8],
) -> Result<RelinquishCertificateResult, WalletError> {
    Ok(RelinquishCertificateResult { relinquished: true })
}
