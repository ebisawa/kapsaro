// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH wire format primitives.
//!
//! Implements SSH_STRING encoding/decoding per SSH protocol RFC 4251 §5.

use crate::io::ssh::SshError;
use crate::Result;

/// Bytes the big-endian length field occupies ahead of the payload.
const LENGTH_PREFIX_SIZE: usize = 4;

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
/// # Errors
///
/// - `Error::Ssh` - The payload is longer than the length field can state
pub fn encode_ssh_string(data: &[u8]) -> Result<Vec<u8>> {
    let len = u32::try_from(data.len()).map_err(|_| {
        SshError::build_operation_failed_error(format!(
            "SSH_STRING payload of {} bytes exceeds the {} bytes the length field can state",
            data.len(),
            u32::MAX
        ))
    })?;
    let mut result = len.to_be_bytes().to_vec();
    result.extend_from_slice(data);
    Ok(result)
}

/// Decode SSH_STRING from bytes, returning (data, remaining_bytes)
///
/// The length field spans the whole `u32` range, and adding the prefix to it
/// overflows a 32-bit `usize`. The sum is taken with an overflow check, so a
/// declared length no address space can hold is reported instead of wrapping
/// past the bounds check below it.
///
/// # Errors
///
/// - `Error::Ssh` - Insufficient data for length field or payload
pub fn decode_ssh_string(data: &[u8]) -> Result<(&[u8], &[u8])> {
    if data.len() < LENGTH_PREFIX_SIZE {
        return Err(SshError::build_operation_failed_error(
            "Insufficient data for SSH_STRING length field",
        )
        .into());
    }

    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let end = len.checked_add(LENGTH_PREFIX_SIZE).ok_or_else(|| {
        SshError::build_operation_failed_error(format!(
            "SSH_STRING declares {} bytes, more than this platform can address",
            len
        ))
    })?;

    if data.len() < end {
        return Err(SshError::build_operation_failed_error(format!(
            "Expected {} bytes for SSH_STRING, got {}",
            end,
            data.len()
        ))
        .into());
    }

    Ok((&data[LENGTH_PREFIX_SIZE..end], &data[end..]))
}

#[cfg(test)]
#[path = "../../../../tests/unit/internal/io_ssh_protocol_wire_test.rs"]
mod io_ssh_protocol_wire_test;
