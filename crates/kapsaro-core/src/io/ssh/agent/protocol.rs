// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::validation::AgentIdentity;
use crate::io::ssh::protocol::constants::KEY_TYPE_ED25519;
use crate::io::ssh::protocol::types::Ed25519RawSignature;
use crate::io::ssh::protocol::wire::{decode_ssh_string, encode_ssh_string};
use crate::io::ssh::SshError;
use crate::Result;

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;

pub(super) const MAX_AGENT_PACKET_SIZE: usize = 1024 * 1024;

/// Upper bound on identities accepted from an agent response.
///
/// The declared count is read before any identity is parsed, so it has to be
/// bounded independently of the packet size.
const MAX_AGENT_IDENTITIES: usize = 256;

pub(super) fn build_request_identities() -> Vec<u8> {
    vec![SSH_AGENTC_REQUEST_IDENTITIES]
}

pub(super) fn build_sign_request(public_key_blob: &[u8], message: &[u8]) -> Vec<u8> {
    let mut body = vec![SSH_AGENTC_SIGN_REQUEST];
    body.extend_from_slice(&encode_ssh_string(public_key_blob));
    body.extend_from_slice(&encode_ssh_string(message));
    body.extend_from_slice(&0u32.to_be_bytes());
    body
}

pub(super) fn parse_identities_response(packet: &[u8]) -> Result<Vec<AgentIdentity>> {
    let (message_type, payload) = split_packet(packet)?;
    match message_type {
        SSH_AGENT_IDENTITIES_ANSWER => parse_identities(payload),
        SSH_AGENT_FAILURE => Err(SshError::build_operation_failed_error(
            "ssh-agent rejected identities request",
        )
        .into()),
        other => Err(SshError::build_operation_failed_error(format!(
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
        SSH_AGENT_FAILURE => {
            Err(SshError::build_operation_failed_error("ssh-agent sign failed").into())
        }
        other => Err(SshError::build_operation_failed_error(format!(
            "ssh-agent returned unexpected response type {} to sign request",
            other
        ))
        .into()),
    }
}

fn split_packet(packet: &[u8]) -> Result<(u8, &[u8])> {
    let Some((&message_type, payload)) = packet.split_first() else {
        return Err(
            SshError::build_operation_failed_error("ssh-agent returned an empty response").into(),
        );
    };
    Ok((message_type, payload))
}

fn parse_identities(mut payload: &[u8]) -> Result<Vec<AgentIdentity>> {
    let count = decode_u32(&mut payload, "identity count")?;
    if count > MAX_AGENT_IDENTITIES {
        return Err(SshError::build_operation_failed_error(format!(
            "ssh-agent reported {} identities (maximum {})",
            count, MAX_AGENT_IDENTITIES
        ))
        .into());
    }
    let mut identities = Vec::with_capacity(count);

    for _ in 0..count {
        let (key_blob, rest) = decode_ssh_string(payload)?;
        let (comment, rest) = parse_utf8_string(rest)?;
        identities.push(AgentIdentity::new(key_blob.to_vec(), comment));
        payload = rest;
    }

    if !payload.is_empty() {
        return Err(SshError::build_operation_failed_error(
            "ssh-agent identities response contains unexpected trailing data",
        )
        .into());
    }

    Ok(identities)
}

fn parse_signature(payload: &[u8]) -> Result<Ed25519RawSignature> {
    let (signature_blob, rest) = decode_ssh_string(payload)?;
    if !rest.is_empty() {
        return Err(SshError::build_operation_failed_error(
            "ssh-agent sign response contains unexpected trailing data",
        )
        .into());
    }

    let (algorithm, rest) = decode_ssh_string(signature_blob)?;
    if algorithm != KEY_TYPE_ED25519.as_bytes() {
        let algorithm = std::str::from_utf8(algorithm).unwrap_or("<non-utf8>");
        return Err(SshError::build_operation_failed_error(format!(
            "ssh-agent returned unsupported signature algorithm '{}'",
            algorithm
        ))
        .into());
    }

    let (raw_signature, rest) = decode_ssh_string(rest)?;
    if !rest.is_empty() {
        return Err(SshError::build_operation_failed_error(
            "ssh-agent signature blob contains unexpected trailing data",
        )
        .into());
    }

    Ed25519RawSignature::from_slice(raw_signature)
}

fn parse_utf8_string(payload: &[u8]) -> Result<(String, &[u8])> {
    let (bytes, rest) = decode_ssh_string(payload)?;
    let value = std::str::from_utf8(bytes).map_err(|e| {
        crate::Error::from(SshError::build_operation_failed_error_with_source(
            format!("ssh-agent returned invalid UTF-8: {}", e),
            e,
        ))
    })?;
    Ok((value.to_string(), rest))
}

fn decode_u32(payload: &mut &[u8], field_name: &str) -> Result<usize> {
    if payload.len() < 4 {
        return Err(SshError::build_operation_failed_error(format!(
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
#[path = "../../../../tests/unit/internal/io_ssh_agent_protocol_test.rs"]
mod io_ssh_agent_protocol_test;
