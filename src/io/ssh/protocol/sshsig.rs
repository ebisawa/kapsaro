// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSHSIG format handling (Phase 11.2 - TDD Green phase)
//!
//! Implements SSHSIG wire format parsing and signed data construction
//! per OpenSSH PROTOCOL.sshsig specification.

use super::base64::decode_base64_armored;
use super::types::SshSignatureBlob;
use super::wire::{ssh_string_decode, ssh_string_encode};
use crate::io::ssh::SshError;
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
    result.extend_from_slice(&ssh_string_encode(namespace.as_bytes()));
    result.extend_from_slice(&ssh_string_encode(b"")); // reserved (empty)
    result.extend_from_slice(&ssh_string_encode(SSHSIG_HASHALG.as_bytes()));
    result.extend_from_slice(&ssh_string_encode(&hash));

    result
}
/// Validate SSHSIG magic and version
///
/// Returns the remaining bytes after magic and version fields.
fn validate_sshsig_header(blob: &[u8]) -> Result<&[u8]> {
    // Check minimum length
    if blob.len() < 6 {
        return Err(SshError::operation_failed(
            "SSHSIG blob too short (minimum 10 bytes required)",
        )
        .into());
    }

    // Check magic
    if &blob[0..6] != SSHSIG_MAGIC {
        return Err(SshError::operation_failed(format!(
            "Invalid SSHSIG magic bytes (expected {:?}, got {:?})",
            SSHSIG_MAGIC,
            &blob[0..6.min(blob.len())]
        ))
        .into());
    }

    // Check version field present
    if blob.len() < 10 {
        return Err(
            SshError::operation_failed("SSHSIG blob too short (missing version field)").into(),
        );
    }

    // Parse version (uint32)
    let version = u32::from_be_bytes([blob[6], blob[7], blob[8], blob[9]]);
    if version != 1 {
        return Err(SshError::operation_failed(format!(
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
        return Err(SshError::operation_failed(format!(
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
        return Err(SshError::operation_failed(format!(
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
        return Err(SshError::operation_failed(format!(
            "Unsupported SSHSIG hash algorithm: '{}' (only 'sha256' is supported)",
            String::from_utf8_lossy(hashalg)
        ))
        .into());
    }
    Ok(())
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
/// use secretenv::io::ssh::protocol::sshsig::parse_sshsig_blob;
/// let blob = /* SSHSIG binary data */;
/// let sig_blob = parse_sshsig_blob(&blob, "secretenv-key-protection")?;
/// let ikm = sig_blob.extract_ed25519_raw()?;
/// // Use ikm for HKDF key derivation
/// ```
pub fn parse_sshsig_blob(blob: &[u8], expected_namespace: &str) -> Result<SshSignatureBlob> {
    // Validate magic and version
    let mut cursor = validate_sshsig_header(blob)?;

    // Parse publickey (skip - we don't need it for IKM extraction)
    let (_publickey, rest) = ssh_string_decode(cursor)?;
    cursor = rest;

    // Parse and validate namespace
    let (namespace, rest) = ssh_string_decode(cursor)?;
    validate_namespace(namespace, expected_namespace)?;
    cursor = rest;

    // Parse and validate reserved field
    let (reserved, rest) = ssh_string_decode(cursor)?;
    validate_reserved(reserved)?;
    cursor = rest;

    // Parse and validate hash algorithm
    let (hashalg, rest) = ssh_string_decode(cursor)?;
    validate_hashalg(hashalg)?;
    cursor = rest;

    // Parse signature - THIS IS THE SSH SIGNATURE BLOB
    let (signature_blob, _rest) = ssh_string_decode(cursor)?;

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
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use secretenv::io::ssh::protocol::sshsig::parse_sshsig_armored;
/// let armored = std::fs::read_to_string("message.sig")?;
/// let sig_blob = parse_sshsig_armored(&armored, "secretenv-key-protection")?;
/// let ikm = sig_blob.extract_ed25519_raw()?;
/// # Ok(())
/// # }
/// ```
pub fn parse_sshsig_armored(armored: &str, expected_namespace: &str) -> Result<SshSignatureBlob> {
    let blob = decode_base64_armored(armored)?;
    parse_sshsig_blob(&blob, expected_namespace)
}
