// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for SSH wire format primitives (Phase 11.1 - TDD Red phase)

use crate::io::ssh::protocol::wire::{decode_ssh_string, encode_ssh_string};

#[test]
fn test_ssh_string_encode_empty() {
    let result = encode_ssh_string(b"");
    assert_eq!(result, vec![0, 0, 0, 0]);
}

#[test]
fn test_ssh_string_encode_short() {
    let result = encode_ssh_string(b"test");
    assert_eq!(result, vec![0, 0, 0, 4, b't', b'e', b's', b't']);
}

#[test]
fn test_ssh_string_encode_256_bytes() {
    let data = vec![0x42u8; 256];
    let result = encode_ssh_string(&data);
    // Length: 0x00000100 (256 in big-endian)
    assert_eq!(&result[0..4], &[0, 0, 1, 0]);
    assert_eq!(result.len(), 4 + 256);
    assert_eq!(&result[4..], data.as_slice());
}

#[test]
fn test_ssh_string_decode_roundtrip() {
    let encoded = encode_ssh_string(b"hello");
    let (decoded, rest) = decode_ssh_string(&encoded).unwrap();
    assert_eq!(decoded, b"hello");
    assert_eq!(rest.len(), 0usize);
}

#[test]
fn test_ssh_string_decode_multiple() {
    let mut data = Vec::new();
    data.extend_from_slice(&encode_ssh_string(b"first"));
    data.extend_from_slice(&encode_ssh_string(b"second"));

    let (first, rest) = decode_ssh_string(&data).unwrap();
    assert_eq!(first, b"first");

    let (second, rest) = decode_ssh_string(rest).unwrap();
    assert_eq!(second, b"second");
    assert_eq!(rest.len(), 0usize);
}

#[test]
fn test_ssh_string_decode_insufficient_data_for_length() {
    // Only 3 bytes when we need 4 for length
    let result = decode_ssh_string(&[0, 0, 0]);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Insufficient") || err_msg.contains("length"));
}

#[test]
fn test_ssh_string_decode_insufficient_data_for_payload() {
    // Length says 10 bytes, but only 2 bytes follow
    let result = decode_ssh_string(&[0, 0, 0, 10, 1, 2]);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Expected") || err_msg.contains("bytes"));
}

#[test]
fn test_ssh_string_decode_with_trailing_data() {
    let mut data = encode_ssh_string(b"test");
    data.extend_from_slice(b"trailing");

    let (decoded, rest) = decode_ssh_string(&data).unwrap();
    assert_eq!(decoded, b"test");
    assert_eq!(rest, b"trailing");
}

#[test]
fn test_ssh_string_decode_zero_length() {
    let data = vec![0, 0, 0, 0]; // Empty string
    let (decoded, rest) = decode_ssh_string(&data).unwrap();
    assert_eq!(decoded, b"");
    assert_eq!(rest.len(), 0usize);
}

#[test]
fn test_ssh_string_encode_large() {
    // Test with 1MB of data
    let large_data = vec![0xAAu8; 1024 * 1024];
    let encoded = encode_ssh_string(&large_data);

    let len_bytes = u32::to_be_bytes(1024 * 1024);
    assert_eq!(&encoded[0..4], &len_bytes);
    assert_eq!(encoded.len(), 4 + 1024 * 1024);
}
