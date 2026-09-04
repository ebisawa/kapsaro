// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Attestation verification using raw Ed25519 signatures.
//!
//! Builds the SSHSIG signed data and checks it in process, without ssh-keygen.

use super::protocol::parse::decode_ssh_public_key_blob;
use super::protocol::{sshsig, wire};
use crate::crypto::sign::verify_detached_signature;
use crate::format::codec::base64_public::decode_base64url_nopad_array;
use crate::format::public_key::{build_attestation_body_bytes, AttestationBodyInput};
use crate::io::ssh::protocol::constants as ssh;
use crate::io::ssh::SshError;
use crate::Result;
use ed25519_dalek::VerifyingKey;

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_ssh_verify_test.rs"]
mod io_ssh_verify_test;

/// Build signed data for PublicKey attestation verification.
pub fn build_attestation_signed_data(input: &AttestationBodyInput<'_>) -> Result<Vec<u8>> {
    let attestation_body = build_attestation_body_bytes(input).map_err(|e| {
        crate::Error::from(SshError::build_operation_failed_error_with_source(
            format!("Failed to normalize PublicKey attestation body: {}", e),
            e,
        ))
    })?;

    sshsig::build_sshsig_signed_data(&attestation_body, ssh::ATTESTATION_NAMESPACE)
}

/// Decode attestation signature from base64url
fn decode_attestation_signature(sig_b64url: &str) -> Result<ed25519_dalek::Signature> {
    let sig_bytes: [u8; 64] = decode_base64url_nopad_array(sig_b64url, "attestation signature")
        .map_err(|e| {
            crate::Error::from(SshError::build_operation_failed_error_with_source(
                format!("Failed to decode attestation signature: {}", e),
                e,
            ))
        })?;

    ed25519_dalek::Signature::from_slice(&sig_bytes).map_err(|e| {
        SshError::build_operation_failed_error_with_source(
            format!("Invalid Ed25519 signature: {}", e),
            e,
        )
        .into()
    })
}

/// Extract Ed25519 public key from SSH public key format
fn extract_ed25519_pubkey_from_ssh(ssh_pubkey: &str) -> Result<VerifyingKey> {
    // Parse SSH public key blob
    let pubkey_blob = decode_ssh_public_key_blob(ssh_pubkey)?;
    // SSH public key blob format: [key_type_len(4)][key_type][public_key_len(4)][public_key]
    // Parse using SSH_STRING format
    let (key_type, rest) = wire::decode_ssh_string(&pubkey_blob)?;
    if key_type != ssh::KEY_TYPE_ED25519.as_bytes() {
        return Err(SshError::build_operation_failed_error(format!(
            "Unsupported key type: expected '{}', got '{}'",
            ssh::KEY_TYPE_ED25519,
            String::from_utf8_lossy(key_type)
        ))
        .into());
    }
    let (ed25519_pubkey_bytes, rest) = wire::decode_ssh_string(rest)?;
    if !rest.is_empty() {
        return Err(SshError::build_operation_failed_error(
            "SSH public key blob contains unexpected trailing data",
        )
        .into());
    }
    if ed25519_pubkey_bytes.len() != 32 {
        return Err(SshError::build_operation_failed_error(format!(
            "Invalid Ed25519 public key length: expected 32 bytes, got {}",
            ed25519_pubkey_bytes.len()
        ))
        .into());
    }
    let ed25519_pubkey_bytes: [u8; 32] = ed25519_pubkey_bytes.try_into().map_err(|_| {
        crate::Error::from(SshError::build_operation_failed_error(
            "Failed to convert Ed25519 public key to array",
        ))
    })?;

    VerifyingKey::from_bytes(&ed25519_pubkey_bytes).map_err(|e| {
        crate::Error::from(SshError::build_operation_failed_error_with_source(
            format!("Invalid Ed25519 public key: {}", e),
            e,
        ))
    })
}

/// Verify attestation signature.
///
/// Verification steps:
/// 1. Build and normalize the PublicKey attestation body with JCS
/// 2. Compute the SSHSIG signed_data with the attestation namespace
/// 3. Verify `sig` with `pub`
///
/// # Arguments
///
/// * `input` - PublicKey statement data covered by attestation
/// * `method` - Attestation method, currently only "ssh-sign"
/// * `ssh_pubkey` - SSH public key in OpenSSH format (from attestation.pub)
/// * `sig_b64url` - Base64url-encoded Ed25519 raw signature (64 bytes)
///
/// # Returns
///
/// Ok(()) if signature is valid, error otherwise
pub fn verify_attestation(
    input: &AttestationBodyInput<'_>,
    method: &str,
    ssh_pubkey: &str,
    sig_b64url: &str,
) -> Result<()> {
    if method != ssh::ATTESTATION_METHOD_SSH_SIGN {
        return Err(SshError::build_operation_failed_error(format!(
            "Unsupported attestation method: {}",
            method
        ))
        .into());
    }

    // Step 1: Build signed data
    let signed_data = build_attestation_signed_data(input)?;

    // Step 2: Decode signature
    let sig = decode_attestation_signature(sig_b64url)?;

    // Step 3: Extract Ed25519 public key from SSH format
    let verifying_key = extract_ed25519_pubkey_from_ssh(ssh_pubkey)?;

    // Step 4: Verify signature
    verify_detached_signature(&signed_data, &verifying_key, &sig).map_err(|e| {
        crate::Error::from(SshError::build_operation_failed_error_with_source(
            format!("Attestation signature verification failed: {}", e),
            e,
        ))
    })?;

    Ok(())
}
