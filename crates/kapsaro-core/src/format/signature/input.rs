// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Domain-framed artifact signature inputs.
//!
//! Builds the PRD-defined MAC message and Ed25519 input bytes without changing framing.

use serde::Serialize;

use crate::format::jcs;
use crate::model::wire::context::{MAC_DOMAIN_KEY_POSSESSION_V1, SIG_DOMAIN_ARTIFACT_SIGNATURE_V1};
use crate::Result;

use super::body::ArtifactBodyBytes;

pub(crate) fn build_key_possession_mac_message(
    body_bytes: &ArtifactBodyBytes,
    signer_kid: &str,
) -> Vec<u8> {
    build_domain_framed_bytes(
        MAC_DOMAIN_KEY_POSSESSION_V1.as_bytes(),
        &[body_bytes.as_bytes(), signer_kid.as_bytes()],
    )
}

pub(crate) fn build_artifact_signature_input(
    signature_alg: &str,
    signer_kid: &str,
    body_bytes: &ArtifactBodyBytes,
    mac_string: &str,
) -> Result<Vec<u8>> {
    let header = build_artifact_signature_header(signature_alg, signer_kid)?;
    Ok(build_domain_framed_bytes(
        SIG_DOMAIN_ARTIFACT_SIGNATURE_V1.as_bytes(),
        &[
            header.as_slice(),
            body_bytes.as_bytes(),
            mac_string.as_bytes(),
        ],
    ))
}

#[derive(Serialize)]
struct ArtifactSignatureHeader<'a> {
    alg: &'a str,
    kid: &'a str,
}

fn build_artifact_signature_header(signature_alg: &str, signer_kid: &str) -> Result<Vec<u8>> {
    jcs::normalize(&ArtifactSignatureHeader {
        alg: signature_alg,
        kid: signer_kid,
    })
}

fn build_domain_framed_bytes(domain: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let capacity = domain.len() + fields.iter().map(|field| framed_len(field)).sum::<usize>();
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(domain);
    fields
        .iter()
        .for_each(|field| append_framed_field(&mut output, field));
    output
}

fn append_framed_field(output: &mut Vec<u8>, field: &[u8]) {
    output.extend_from_slice(field.len().to_string().as_bytes());
    output.push(b':');
    output.extend_from_slice(field);
}

fn framed_len(field: &[u8]) -> usize {
    field.len().to_string().len() + 1 + field.len()
}
