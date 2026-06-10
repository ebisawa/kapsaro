// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH wire format primitives (Phase 11.2 - TDD Green phase)
//!
//! Implements SSH_STRING encoding/decoding per SSH protocol RFC 4251 §5.

use crate::io::ssh::SshError;
use crate::Result;

/// Encode data as SSH_STRING: uint32be(length) + bytes
///
/// # SSH Protocol Format
///
/// ```text
/// SSH_STRING:
///   uint32    length (big-endian)
///   byte[n]   data (where n = length)
/// ```
///
/// # Examples
///
/// ```ignore
/// use kapsaro_core::io::ssh::protocol::wire::encode_ssh_string;
/// let encoded = encode_ssh_string(b"test");
/// assert_eq!(encoded, vec![0, 0, 0, 4, b't', b'e', b's', b't']);
/// ```
pub fn encode_ssh_string(data: &[u8]) -> Vec<u8> {
    let len = data.len() as u32;
    let mut result = len.to_be_bytes().to_vec();
    result.extend_from_slice(data);
    result
}

/// Decode SSH_STRING from bytes, returning (data, remaining_bytes)
///
/// # Errors
///
/// - `Error::Ssh` - Insufficient data for length field or payload
///
/// # Examples
///
/// ```ignore
/// use kapsaro_core::io::ssh::protocol::wire::{decode_ssh_string, encode_ssh_string};
/// let encoded = encode_ssh_string(b"hello");
/// let (decoded, rest): (&[u8], &[u8]) = decode_ssh_string(&encoded).unwrap();
/// assert_eq!(decoded, b"hello");
/// assert_eq!(rest.len(), 0);
/// ```
pub fn decode_ssh_string(data: &[u8]) -> Result<(&[u8], &[u8])> {
    if data.len() < 4 {
        return Err(SshError::build_operation_failed_error(
            "Insufficient data for SSH_STRING length field",
        )
        .into());
    }

    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;

    if data.len() < 4 + len {
        return Err(SshError::build_operation_failed_error(format!(
            "Expected {} bytes for SSH_STRING, got {}",
            4 + len,
            data.len()
        ))
        .into());
    }

    Ok((&data[4..4 + len], &data[4 + len..]))
}

#[cfg(test)]
#[path = "../../../../tests/unit/internal/io_ssh_protocol_wire_test.rs"]
mod io_ssh_protocol_wire_test;
