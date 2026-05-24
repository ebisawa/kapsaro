// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSHSIG verification via ssh-keygen subprocess
//!
//! Also provides attestation verification using raw Ed25519 signatures.

use super::protocol::parse::decode_ssh_public_key_blob;
use super::protocol::{sshsig, wire};
use crate::format::codec::base64_public::decode_base64url_nopad_array;
use crate::format::jcs;
use crate::io::ssh::external::traits::SshKeygen;
use crate::io::ssh::protocol::constants as ssh;
use crate::io::ssh::SshError;
use crate::model::public_key::IdentityKeys;
use crate::Result;
use ed25519_dalek::{Verifier, VerifyingKey};

/// Validate SSHSIG inputs before verification.
///
/// Returns an error if validation fails, otherwise returns Ok(()).
pub fn validate_sshsig_inputs(ssh_pubkey: &str, signature: &str) -> Result<()> {
    if ssh_pubkey.is_empty() {
        return Err(SshError::build_operation_failed_error("SSH public key is empty").into());
    }

    let key_type = ssh_pubkey.split_whitespace().next().unwrap_or("");
    if key_type != ssh::KEY_TYPE_ED25519 {
        return Err(SshError::build_operation_failed_error(format!(
            "Only ssh-ed25519 supported, got: {}",
            key_type
        ))
        .into());
    }

    if signature.is_empty() {
        return Err(SshError::build_operation_failed_error("Signature is empty").into());
    }

    if !signature.contains(ssh::SSHSIG_ARMOR_BEGIN) {
        return Err(SshError::build_operation_failed_error("Not in SSHSIG armored format").into());
    }

    Ok(())
}

/// Verify an SSHSIG armored signature using the `SshKeygen` trait.
pub fn verify_sshsig(
    ssh_keygen: &dyn SshKeygen,
    ssh_pubkey: &str,
    message: &[u8],
    signature: &str,
) -> Result<()> {
    validate_sshsig_inputs(ssh_pubkey, signature)?;
    ssh_keygen.verify(ssh_pubkey, ssh::ATTESTATION_NAMESPACE, message, signature)
}

/// Build signed data for attestation verification
pub fn build_attestation_signed_data(identity_keys: &IdentityKeys) -> Result<Vec<u8>> {
    // JCS normalize identity.keys
    let identity_keys_jcs = jcs::normalize(identity_keys).map_err(|e| {
        crate::Error::from(SshError::build_operation_failed_error_with_source(
            format!("Failed to normalize identity.keys: {}", e),
            e,
        ))
    })?;

    // Build signed_data with the attestation namespace
    Ok(sshsig::build_sshsig_signed_data(
        &identity_keys_jcs,
        ssh::ATTESTATION_NAMESPACE,
    ))
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
/// 1. Normalize the `identity.keys` object using JCS
/// 2. Compute the SHA256 of the normalized bytes
/// 3. Verify `sig` with `pub` using the attestation namespace
///
/// # Arguments
///
/// * `identity_keys` - IdentityKeys object (JCS normalized bytes will be computed)
/// * `ssh_pubkey` - SSH public key in OpenSSH format (from attestation.pub)
/// * `sig_b64url` - Base64url-encoded Ed25519 raw signature (64 bytes)
///
/// # Returns
///
/// Ok(()) if signature is valid, error otherwise
pub fn verify_attestation(
    identity_keys: &IdentityKeys,
    ssh_pubkey: &str,
    sig_b64url: &str,
) -> Result<()> {
    // Step 1: Build signed data
    let signed_data = build_attestation_signed_data(identity_keys)?;

    // Step 2: Decode signature
    let sig = decode_attestation_signature(sig_b64url)?;

    // Step 3: Extract Ed25519 public key from SSH format
    let verifying_key = extract_ed25519_pubkey_from_ssh(ssh_pubkey)?;

    // Step 4: Verify signature
    verifying_key.verify(&signed_data, &sig).map_err(|e| {
        crate::Error::from(SshError::build_operation_failed_error_with_source(
            format!("Attestation signature verification failed: {}", e),
            e,
        ))
    })?;

    Ok(())
}
