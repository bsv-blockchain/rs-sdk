//! Request and result frame protocol for wallet wire communication.

use super::read_varint;
use crate::wallet::error::WalletError;

/// A wallet wire protocol request frame.
pub struct RequestFrame {
    pub call: u8,
    pub originator: String,
    pub params: Vec<u8>,
}

/// Serialize a request frame: `[call_byte][originator_len_byte][originator_bytes][params_bytes]`.
pub fn write_request_frame(frame: &RequestFrame) -> Vec<u8> {
    let originator_bytes = frame.originator.as_bytes();
    let mut buf = Vec::with_capacity(1 + 1 + originator_bytes.len() + frame.params.len());
    buf.push(frame.call);
    buf.push(originator_bytes.len() as u8);
    buf.extend_from_slice(originator_bytes);
    buf.extend_from_slice(&frame.params);
    buf
}

/// Parse a request frame from raw bytes.
pub fn read_request_frame(data: &[u8]) -> Result<RequestFrame, WalletError> {
    if data.len() < 2 {
        return Err(WalletError::Internal("request frame too short".to_string()));
    }
    let call = data[0];
    let originator_len = data[1] as usize;
    if data.len() < 2 + originator_len {
        return Err(WalletError::Internal(
            "request frame originator truncated".to_string(),
        ));
    }
    let originator = String::from_utf8(data[2..2 + originator_len].to_vec())
        .map_err(|e| WalletError::Internal(e.to_string()))?;
    let params = data[2 + originator_len..].to_vec();
    Ok(RequestFrame {
        call,
        originator,
        params,
    })
}

/// Write a result frame.
/// Success: `[0x00][result_bytes]`.
/// Error: `[code_byte][msg_varint_len][msg][stack_varint_len][stack]`.
pub fn write_result_frame(result: Option<&[u8]>, error: Option<&WalletError>) -> Vec<u8> {
    let mut buf = Vec::new();
    if let Some(err) = error {
        match err {
            WalletError::Protocol { code, message } => {
                buf.push(*code);
                let msg_bytes = message.as_bytes();
                buf.extend_from_slice(&super::varint_bytes(msg_bytes.len() as u64));
                buf.extend_from_slice(msg_bytes);
                // Empty stack
                buf.extend_from_slice(&super::varint_bytes(0));
            }
            _ => {
                let msg = err.to_string();
                buf.push(1); // generic error code
                let msg_bytes = msg.as_bytes();
                buf.extend_from_slice(&super::varint_bytes(msg_bytes.len() as u64));
                buf.extend_from_slice(msg_bytes);
                buf.extend_from_slice(&super::varint_bytes(0));
            }
        }
    } else {
        buf.push(0x00); // success
        if let Some(data) = result {
            buf.extend_from_slice(data);
        }
    }
    buf
}

/// Read a result frame. Returns Ok(result_bytes) on success, Err on error frame.
pub fn read_result_frame(data: &[u8]) -> Result<Vec<u8>, WalletError> {
    if data.is_empty() {
        return Err(WalletError::Internal("empty result frame".to_string()));
    }
    let error_byte = data[0];
    if error_byte == 0 {
        // Success
        return Ok(data[1..].to_vec());
    }
    // Error frame
    let mut cursor = std::io::Cursor::new(&data[1..]);
    let msg_len = read_varint(&mut cursor)?;
    let mut msg_buf = vec![0u8; msg_len as usize];
    std::io::Read::read_exact(&mut cursor, &mut msg_buf)
        .map_err(|e| WalletError::Internal(e.to_string()))?;
    let message = String::from_utf8(msg_buf).map_err(|e| WalletError::Internal(e.to_string()))?;

    let stack_len = read_varint(&mut cursor)?;
    let mut stack_buf = vec![0u8; stack_len as usize];
    std::io::Read::read_exact(&mut cursor, &mut stack_buf)
        .map_err(|e| WalletError::Internal(e.to_string()))?;

    Err(WalletError::Protocol {
        code: error_byte,
        message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_frame_roundtrip() {
        let frame = RequestFrame {
            call: 11,
            originator: "test-app".to_string(),
            params: vec![1, 2, 3, 4],
        };
        let wire = write_request_frame(&frame);
        let parsed = read_request_frame(&wire).unwrap();
        assert_eq!(parsed.call, 11);
        assert_eq!(parsed.originator, "test-app");
        assert_eq!(parsed.params, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_request_frame_empty_originator() {
        let frame = RequestFrame {
            call: 1,
            originator: String::new(),
            params: vec![5, 6],
        };
        let wire = write_request_frame(&frame);
        assert_eq!(wire[0], 1);
        assert_eq!(wire[1], 0);
        assert_eq!(&wire[2..], &[5, 6]);
        let parsed = read_request_frame(&wire).unwrap();
        assert_eq!(parsed.call, 1);
        assert_eq!(parsed.originator, "");
        assert_eq!(parsed.params, vec![5, 6]);
    }

    #[test]
    fn test_result_frame_success() {
        let wire = write_result_frame(Some(&[1, 2, 3]), None);
        assert_eq!(wire[0], 0);
        let data = read_result_frame(&wire).unwrap();
        assert_eq!(data, vec![1, 2, 3]);
    }

    #[test]
    fn test_result_frame_success_empty() {
        let wire = write_result_frame(None, None);
        assert_eq!(wire, vec![0]);
        let data = read_result_frame(&wire).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn test_result_frame_error() {
        let err = WalletError::Protocol {
            code: 5,
            message: "test error".to_string(),
        };
        let wire = write_result_frame(None, Some(&err));
        assert_ne!(wire[0], 0);
        let result = read_result_frame(&wire);
        assert!(result.is_err());
    }
}
