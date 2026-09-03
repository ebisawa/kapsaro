// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the ssh-agent wire protocol encoder and decoder.
//! Covers request framing, response parsing, and rejected inputs.

use super::{
    build_request_identities, build_sign_request, parse_identities_response, parse_sign_response,
};
use crate::io::ssh::protocol::parse::decode_ssh_public_key_blob;
use crate::io::ssh::protocol::wire::encode_ssh_string;

const TEST_AGENT_PUBLIC_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGkB6jid+Y/7wt0S+9jTJGX1UytxIHOO3GXVPZPY1OYT test-agent";

fn build_identities_packet(identity_count: u32) -> Vec<u8> {
    let mut packet = vec![12];
    packet.extend_from_slice(&identity_count.to_be_bytes());
    packet
}

fn append_identity(packet: &mut Vec<u8>, key_blob: &[u8], comment: &[u8]) {
    packet.extend_from_slice(&encode_ssh_string(key_blob).unwrap());
    packet.extend_from_slice(&encode_ssh_string(comment).unwrap());
}

#[test]
fn test_build_request_identities_packet_body() {
    assert_eq!(build_request_identities(), vec![11]);
}

#[test]
fn test_parse_identities_response_count_exceeds_empty_payload_capacity_error() {
    let packet = build_identities_packet(u32::MAX);

    let error = parse_identities_response(&packet).unwrap_err();

    assert!(
        error.to_string().contains("payload capacity is 0"),
        "unexpected error: {error}",
    );
}

#[test]
fn test_parse_identities_response_count_exceeds_single_identity_payload_capacity_error() {
    let mut packet = build_identities_packet(2);
    append_identity(&mut packet, &[], &[]);

    let error = parse_identities_response(&packet).unwrap_err();

    assert!(
        error.to_string().contains("payload capacity is 1"),
        "unexpected error: {error}",
    );
}

#[test]
fn test_parse_identities_response_incomplete_ssh_string_after_capacity_check_error() {
    let mut packet = build_identities_packet(1);
    packet.extend_from_slice(&5u32.to_be_bytes());
    packet.extend_from_slice(&[1, 2, 3, 4]);

    let error = parse_identities_response(&packet).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("Expected 9 bytes for SSH_STRING, got 8"),
        "unexpected error: {error}",
    );
}

#[test]
fn test_parse_identities_response_with_257_ed25519_identities() {
    let key_blob = decode_ssh_public_key_blob(TEST_AGENT_PUBLIC_KEY).unwrap();
    let mut packet = build_identities_packet(257);
    for _ in 0..257 {
        append_identity(&mut packet, &key_blob, b"test-agent");
    }

    let identities = parse_identities_response(&packet).unwrap();

    assert_eq!(identities.len(), 257);
    assert!(identities
        .iter()
        .all(|identity| identity.key_blob() == key_blob.as_slice()));
}

#[test]
fn test_parse_identities_response_with_key_blob_and_comment() {
    let key_blob = decode_ssh_public_key_blob(TEST_AGENT_PUBLIC_KEY).unwrap();
    let mut packet = build_identities_packet(1);
    append_identity(&mut packet, &key_blob, b"test-agent");

    let identities = parse_identities_response(&packet).unwrap();

    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].key_blob(), key_blob.as_slice());
}

#[test]
fn test_build_sign_request_with_key_blob_payload() {
    let key_blob = decode_ssh_public_key_blob(TEST_AGENT_PUBLIC_KEY).unwrap();

    let request = build_sign_request(&key_blob, b"payload").unwrap();

    assert_eq!(request[0], 13);
    assert!(request
        .windows(key_blob.len())
        .any(|window| window == key_blob));
}

#[test]
fn test_parse_sign_response_extracts_ed25519_signature() {
    let signature = [7u8; 64];
    let mut signature_blob = Vec::new();
    signature_blob.extend_from_slice(&encode_ssh_string(b"ssh-ed25519").unwrap());
    signature_blob.extend_from_slice(&encode_ssh_string(&signature).unwrap());
    let mut packet = vec![14];
    packet.extend_from_slice(&encode_ssh_string(&signature_blob).unwrap());

    let parsed = parse_sign_response(&packet).unwrap();

    assert_eq!(parsed.as_bytes(), &signature);
}

#[test]
fn test_parse_identities_response_rejects_agent_failure() {
    let error = parse_identities_response(&[5]).unwrap_err();

    assert!(error.to_string().contains("rejected identities request"));
}

#[test]
fn test_parse_identities_response_rejects_unknown_type() {
    let error = parse_identities_response(&[99]).unwrap_err();

    assert!(error.to_string().contains("unexpected response type 99"));
}

#[test]
fn test_parse_identities_response_rejects_empty_packet() {
    let error = parse_identities_response(&[]).unwrap_err();

    assert!(error.to_string().contains("empty response"));
}

#[test]
fn test_parse_identities_response_rejects_trailing_data() {
    let mut packet = vec![12];
    packet.extend_from_slice(&0u32.to_be_bytes());
    packet.push(1);

    let error = parse_identities_response(&packet).unwrap_err();

    assert!(error.to_string().contains("unexpected trailing data"));
}

#[test]
fn test_parse_identities_response_rejects_invalid_utf8_comment() {
    let key_blob = decode_ssh_public_key_blob(TEST_AGENT_PUBLIC_KEY).unwrap();
    let mut packet = vec![12];
    packet.extend_from_slice(&1u32.to_be_bytes());
    packet.extend_from_slice(&encode_ssh_string(&key_blob).unwrap());
    packet.extend_from_slice(&encode_ssh_string(&[0xff]).unwrap());

    let error = parse_identities_response(&packet).unwrap_err();

    assert!(error.to_string().contains("invalid UTF-8"));
}

#[test]
fn test_parse_sign_response_rejects_agent_failure() {
    let error = parse_sign_response(&[5]).unwrap_err();

    assert!(error.to_string().contains("sign failed"));
}

#[test]
fn test_parse_sign_response_rejects_unsupported_signature_algorithm() {
    let signature = [7u8; 64];
    let mut signature_blob = Vec::new();
    signature_blob.extend_from_slice(&encode_ssh_string(b"rsa-sha2-512").unwrap());
    signature_blob.extend_from_slice(&encode_ssh_string(&signature).unwrap());
    let mut packet = vec![14];
    packet.extend_from_slice(&encode_ssh_string(&signature_blob).unwrap());

    let error = parse_sign_response(&packet).unwrap_err();

    assert!(error
        .to_string()
        .contains("unsupported signature algorithm"));
}

#[test]
fn test_parse_sign_response_rejects_invalid_signature_length() {
    let signature = [7u8; 63];
    let mut signature_blob = Vec::new();
    signature_blob.extend_from_slice(&encode_ssh_string(b"ssh-ed25519").unwrap());
    signature_blob.extend_from_slice(&encode_ssh_string(&signature).unwrap());
    let mut packet = vec![14];
    packet.extend_from_slice(&encode_ssh_string(&signature_blob).unwrap());

    let error = parse_sign_response(&packet).unwrap_err();

    assert!(error.to_string().contains("64"));
}

#[test]
fn test_parse_sign_response_rejects_signature_blob_trailing_data() {
    let signature = [7u8; 64];
    let mut signature_blob = Vec::new();
    signature_blob.extend_from_slice(&encode_ssh_string(b"ssh-ed25519").unwrap());
    signature_blob.extend_from_slice(&encode_ssh_string(&signature).unwrap());
    signature_blob.push(1);
    let mut packet = vec![14];
    packet.extend_from_slice(&encode_ssh_string(&signature_blob).unwrap());

    let error = parse_sign_response(&packet).unwrap_err();

    assert!(error.to_string().contains("unexpected trailing data"));
}
