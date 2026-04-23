// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::validation::AgentIdentity;
use crate::io::ssh::protocol::constants::KEY_TYPE_ED25519;
use crate::io::ssh::protocol::types::Ed25519RawSignature;
use crate::io::ssh::protocol::wire::{ssh_string_decode, ssh_string_encode};
use crate::io::ssh::SshError;
use crate::Result;

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;

pub(super) const MAX_AGENT_PACKET_SIZE: usize = 1024 * 1024;

pub(super) fn build_request_identities() -> Vec<u8> {
    vec![SSH_AGENTC_REQUEST_IDENTITIES]
}

pub(super) fn build_sign_request(public_key_blob: &[u8], message: &[u8]) -> Vec<u8> {
    let mut body = vec![SSH_AGENTC_SIGN_REQUEST];
    body.extend_from_slice(&ssh_string_encode(public_key_blob));
    body.extend_from_slice(&ssh_string_encode(message));
    body.extend_from_slice(&0u32.to_be_bytes());
    body
}

pub(super) fn parse_identities_response(packet: &[u8]) -> Result<Vec<AgentIdentity>> {
    let (message_type, payload) = split_packet(packet)?;
    match message_type {
        SSH_AGENT_IDENTITIES_ANSWER => parse_identities(payload),
        SSH_AGENT_FAILURE => {
            Err(SshError::operation_failed("ssh-agent rejected identities request").into())
        }
        other => Err(SshError::operation_failed(format!(
            "ssh-agent returned unexpected response type {} to identities request",
            other
        ))
        .into()),
    }
}

pub(super) fn parse_sign_response(packet: &[u8]) -> Result<Ed25519RawSignature> {
    let (message_type, payload) = split_packet(packet)?;
    match message_type {
        SSH_AGENT_SIGN_RESPONSE => parse_signature(payload),
        SSH_AGENT_FAILURE => Err(SshError::operation_failed("ssh-agent sign failed").into()),
        other => Err(SshError::operation_failed(format!(
            "ssh-agent returned unexpected response type {} to sign request",
            other
        ))
        .into()),
    }
}

fn split_packet(packet: &[u8]) -> Result<(u8, &[u8])> {
    let Some((&message_type, payload)) = packet.split_first() else {
        return Err(SshError::operation_failed("ssh-agent returned an empty response").into());
    };
    Ok((message_type, payload))
}

fn parse_identities(mut payload: &[u8]) -> Result<Vec<AgentIdentity>> {
    let count = read_u32(&mut payload, "identity count")?;
    let mut identities = Vec::with_capacity(count);

    for _ in 0..count {
        let (key_blob, rest) = ssh_string_decode(payload)?;
        let (comment, rest) = parse_utf8_string(rest)?;
        identities.push(AgentIdentity::new(key_blob.to_vec(), comment));
        payload = rest;
    }

    if !payload.is_empty() {
        return Err(SshError::operation_failed(
            "ssh-agent identities response contains unexpected trailing data",
        )
        .into());
    }

    Ok(identities)
}

fn parse_signature(payload: &[u8]) -> Result<Ed25519RawSignature> {
    let (signature_blob, rest) = ssh_string_decode(payload)?;
    if !rest.is_empty() {
        return Err(SshError::operation_failed(
            "ssh-agent sign response contains unexpected trailing data",
        )
        .into());
    }

    let (algorithm, rest) = ssh_string_decode(signature_blob)?;
    if algorithm != KEY_TYPE_ED25519.as_bytes() {
        let algorithm = std::str::from_utf8(algorithm).unwrap_or("<non-utf8>");
        return Err(SshError::operation_failed(format!(
            "ssh-agent returned unsupported signature algorithm '{}'",
            algorithm
        ))
        .into());
    }

    let (raw_signature, rest) = ssh_string_decode(rest)?;
    if !rest.is_empty() {
        return Err(SshError::operation_failed(
            "ssh-agent signature blob contains unexpected trailing data",
        )
        .into());
    }

    Ed25519RawSignature::from_slice(raw_signature)
}

fn parse_utf8_string(payload: &[u8]) -> Result<(String, &[u8])> {
    let (bytes, rest) = ssh_string_decode(payload)?;
    let value = std::str::from_utf8(bytes).map_err(|e| {
        crate::Error::from(SshError::operation_failed_with_source(
            format!("ssh-agent returned invalid UTF-8: {}", e),
            e,
        ))
    })?;
    Ok((value.to_string(), rest))
}

fn read_u32(payload: &mut &[u8], field_name: &str) -> Result<usize> {
    if payload.len() < 4 {
        return Err(SshError::operation_failed(format!(
            "ssh-agent response missing {}",
            field_name
        ))
        .into());
    }
    let value = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    *payload = &payload[4..];
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{
        build_request_identities, build_sign_request, parse_identities_response,
        parse_sign_response,
    };
    use crate::io::ssh::protocol::parse::decode_ssh_public_key_blob;
    use crate::io::ssh::protocol::wire::ssh_string_encode;

    const TEST_AGENT_PUBLIC_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGkB6jid+Y/7wt0S+9jTJGX1UytxIHOO3GXVPZPY1OYT test-agent";

    #[test]
    fn test_build_request_identities_packet_body() {
        assert_eq!(build_request_identities(), vec![11]);
    }

    #[test]
    fn test_parse_identities_response_reads_key_blob_and_comment() {
        let key_blob = decode_ssh_public_key_blob(TEST_AGENT_PUBLIC_KEY).unwrap();
        let mut packet = vec![12];
        packet.extend_from_slice(&1u32.to_be_bytes());
        packet.extend_from_slice(&ssh_string_encode(&key_blob));
        packet.extend_from_slice(&ssh_string_encode(b"test-agent"));

        let identities = parse_identities_response(&packet).unwrap();

        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].key_blob(), key_blob.as_slice());
        assert_eq!(identities[0].comment(), "test-agent");
    }

    #[test]
    fn test_build_sign_request_encodes_key_blob_and_payload() {
        let key_blob = decode_ssh_public_key_blob(TEST_AGENT_PUBLIC_KEY).unwrap();

        let request = build_sign_request(&key_blob, b"payload");

        assert_eq!(request[0], 13);
        assert!(request
            .windows(key_blob.len())
            .any(|window| window == key_blob));
    }

    #[test]
    fn test_parse_sign_response_extracts_ed25519_signature() {
        let signature = [7u8; 64];
        let mut signature_blob = Vec::new();
        signature_blob.extend_from_slice(&ssh_string_encode(b"ssh-ed25519"));
        signature_blob.extend_from_slice(&ssh_string_encode(&signature));
        let mut packet = vec![14];
        packet.extend_from_slice(&ssh_string_encode(&signature_blob));

        let parsed = parse_sign_response(&packet).unwrap();

        assert_eq!(parsed.as_bytes(), &signature);
    }
}
