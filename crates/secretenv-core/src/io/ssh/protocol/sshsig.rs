// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSHSIG format handling (Phase 11.2 - TDD Green phase)
//!
//! Implements SSHSIG wire format parsing and signed data construction
//! per OpenSSH PROTOCOL.sshsig specification.

use super::base64::decode_base64_armored;
use super::parse::decode_ssh_public_key_blob;
use super::types::SshSignatureBlob;
use super::wire::{decode_ssh_string, encode_ssh_string};
use crate::io::ssh::SshError;
use crate::support::codec::base64_public::encode_base64_standard_nopad;
use crate::Result;
use sha2::{Digest, Sha256};

/// SSHSIG magic bytes (6-byte literal)
pub const SSHSIG_MAGIC: &[u8] = b"SSHSIG";

/// Hash algorithm used in SSHSIG (must be "sha256")
pub const SSHSIG_HASHALG: &str = "sha256";

/// Build sshsig_signed_data_bytes with a specific namespace
///
/// This constructs the data structure that gets signed by SSH keys:
///
/// ```text
/// byte[6]      MAGIC
/// SSH_STRING   namespace
/// SSH_STRING   reserved (empty)
/// SSH_STRING   hash_algorithm ("sha256")
/// SSH_STRING   H(message)
/// ```
///
/// # Arguments
///
/// * `message` - The original message to be signed (will be hashed with SHA-256)
/// * `namespace` - The SSHSIG namespace for the signature context
///
/// # Returns
///
/// Byte vector ready to be signed by ssh-agent or ssh-keygen
pub fn build_sshsig_signed_data(message: &[u8], namespace: &str) -> Vec<u8> {
    let hash = Sha256::digest(message);

    let mut result = Vec::new();
    result.extend_from_slice(SSHSIG_MAGIC);
    result.extend_from_slice(&encode_ssh_string(namespace.as_bytes()));
    result.extend_from_slice(&encode_ssh_string(b"")); // reserved (empty)
    result.extend_from_slice(&encode_ssh_string(SSHSIG_HASHALG.as_bytes()));
    result.extend_from_slice(&encode_ssh_string(&hash));

    result
}
/// Validate SSHSIG magic and version
///
/// Returns the remaining bytes after magic and version fields.
fn validate_sshsig_header(blob: &[u8]) -> Result<&[u8]> {
    // Check minimum length
    if blob.len() < 6 {
        return Err(SshError::build_operation_failed_error(
            "SSHSIG blob too short (minimum 10 bytes required)",
        )
        .into());
    }

    // Check magic
    if &blob[0..6] != SSHSIG_MAGIC {
        return Err(SshError::build_operation_failed_error(format!(
            "Invalid SSHSIG magic bytes (expected {:?}, got {:?})",
            SSHSIG_MAGIC,
            &blob[0..6.min(blob.len())]
        ))
        .into());
    }

    // Check version field present
    if blob.len() < 10 {
        return Err(SshError::build_operation_failed_error(
            "SSHSIG blob too short (missing version field)",
        )
        .into());
    }

    // Parse version (uint32)
    let version = u32::from_be_bytes([blob[6], blob[7], blob[8], blob[9]]);
    if version != 1 {
        return Err(SshError::build_operation_failed_error(format!(
            "Unsupported SSHSIG version: {} (only version 1 is supported)",
            version
        ))
        .into());
    }

    Ok(&blob[10..])
}

/// Validate SSHSIG namespace field
fn validate_namespace(namespace: &[u8], expected_namespace: &str) -> Result<()> {
    if namespace != expected_namespace.as_bytes() {
        return Err(SshError::build_operation_failed_error(format!(
            "SSHSIG namespace mismatch: expected '{}', got '{}'",
            expected_namespace,
            String::from_utf8_lossy(namespace)
        ))
        .into());
    }
    Ok(())
}

/// Validate SSHSIG reserved field (must be empty)
fn validate_reserved(reserved: &[u8]) -> Result<()> {
    if !reserved.is_empty() {
        return Err(SshError::build_operation_failed_error(format!(
            "SSHSIG reserved field must be empty, got {} bytes",
            reserved.len()
        ))
        .into());
    }
    Ok(())
}

/// Validate SSHSIG hash algorithm field
fn validate_hashalg(hashalg: &[u8]) -> Result<()> {
    if hashalg != b"sha256" {
        return Err(SshError::build_operation_failed_error(format!(
            "Unsupported SSHSIG hash algorithm: '{}' (only 'sha256' is supported)",
            String::from_utf8_lossy(hashalg)
        ))
        .into());
    }
    Ok(())
}

fn format_publickey_fingerprint(publickey: &[u8]) -> String {
    let hash = Sha256::digest(publickey);
    format!("SHA256:{}", encode_base64_standard_nopad(hash.as_ref()))
}

fn validate_publickey(publickey: &[u8], expected_ssh_pubkey: &str) -> Result<()> {
    let expected_publickey = decode_ssh_public_key_blob(expected_ssh_pubkey)?;
    if publickey == expected_publickey.as_slice() {
        return Ok(());
    }

    Err(SshError::build_operation_failed_error(format!(
        "SSHSIG publickey mismatch: expected {}, got {}",
        format_publickey_fingerprint(&expected_publickey),
        format_publickey_fingerprint(publickey)
    ))
    .into())
}

/// Parse SSHSIG blob and extract signature field (SSH signature blob)
///
/// SSHSIG wire format:
///
/// ```text
/// byte[6]      MAGIC ("SSHSIG")
/// uint32       version (must be 1)
/// SSH_STRING   publickey
/// SSH_STRING   namespace (must match the expected namespace)
/// SSH_STRING   reserved (must be empty)
/// SSH_STRING   hash_algorithm (must be "sha256")
/// SSH_STRING   signature  <-- SSH signature blob (string algorithm + string signature)
/// ```
///
/// # Arguments
///
/// * `blob` - Raw SSHSIG binary blob
/// * `expected_namespace` - Namespace that the SSHSIG blob must carry
/// * `expected_ssh_pubkey` - SSH public key that the SSHSIG publickey field must match
///
/// # Returns
///
/// The signature field bytes (SSH signature blob).
/// In secretenv, this is further normalized to Ed25519 raw signature bytes (64 bytes)
/// before being used as IKM for SA-SIG-KDF.
///
/// # Errors
///
/// - `Error::Ssh` - Invalid magic, wrong version, namespace mismatch, etc.
///
/// # Examples
///
/// ```ignore
/// use secretenv_core::io::ssh::protocol::sshsig::parse_sshsig_blob;
/// let blob = /* SSHSIG binary data */;
/// let expected_ssh_pubkey = "ssh-ed25519 AAAA...";
/// let sig_blob = parse_sshsig_blob(&blob, "secretenv-key-protection", expected_ssh_pubkey)?;
/// let ikm = sig_blob.extract_ed25519_raw()?;
/// // Use ikm for HKDF key derivation
/// ```
pub fn parse_sshsig_blob(
    blob: &[u8],
    expected_namespace: &str,
    expected_ssh_pubkey: &str,
) -> Result<SshSignatureBlob> {
    // Validate magic and version
    let mut cursor = validate_sshsig_header(blob)?;

    // Parse and validate publickey
    let (publickey, rest) = decode_ssh_string(cursor)?;
    validate_publickey(publickey, expected_ssh_pubkey)?;
    cursor = rest;

    // Parse and validate namespace
    let (namespace, rest) = decode_ssh_string(cursor)?;
    validate_namespace(namespace, expected_namespace)?;
    cursor = rest;

    // Parse and validate reserved field
    let (reserved, rest) = decode_ssh_string(cursor)?;
    validate_reserved(reserved)?;
    cursor = rest;

    // Parse and validate hash algorithm
    let (hashalg, rest) = decode_ssh_string(cursor)?;
    validate_hashalg(hashalg)?;
    cursor = rest;

    // Parse signature - THIS IS THE SSH SIGNATURE BLOB
    let (signature_blob, _rest) = decode_ssh_string(cursor)?;

    Ok(SshSignatureBlob::new(signature_blob.to_vec()))
}

/// Parse SSHSIG armored format and extract signature field (SSH signature blob)
///
/// Armored format:
///
/// ```text
/// -----BEGIN SSH SIGNATURE-----
/// <base64-encoded SSHSIG blob, possibly multi-line>
/// -----END SSH SIGNATURE-----
/// ```
///
/// # Arguments
///
/// * `armored` - Armored SSHSIG string (output from ssh-keygen -Y sign)
/// * `expected_namespace` - Namespace that the SSHSIG blob must carry
/// * `expected_ssh_pubkey` - SSH public key that the SSHSIG publickey field must match
///
/// # Returns
///
/// The signature field bytes (SSH signature blob)
///
/// # Errors
///
/// - `Error::Ssh` - No base64 content, invalid base64, or blob parsing failure
///
/// # Examples
///
/// ```ignore
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use secretenv_core::io::ssh::protocol::sshsig::parse_sshsig_armored;
/// let armored = std::fs::read_to_string("message.sig")?;
/// let expected_ssh_pubkey = "ssh-ed25519 AAAA...";
/// let sig_blob = parse_sshsig_armored(&armored, "secretenv-key-protection", expected_ssh_pubkey)?;
/// let ikm = sig_blob.extract_ed25519_raw()?;
/// # Ok(())
/// # }
/// ```
pub fn parse_sshsig_armored(
    armored: &str,
    expected_namespace: &str,
    expected_ssh_pubkey: &str,
) -> Result<SshSignatureBlob> {
    let blob = decode_base64_armored(armored)?;
    parse_sshsig_blob(&blob, expected_namespace, expected_ssh_pubkey)
}
