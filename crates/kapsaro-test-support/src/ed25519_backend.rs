// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

// Ed25519 direct signing backend for tests.
// Replaces SshKeygenBackend to avoid spawning ssh-keygen subprocesses in tests.

use ed25519_dalek::{Signer, SigningKey};
use kapsaro_core::cli_api::test_support::storage::ssh::backend::SignatureBackend;
use kapsaro_core::cli_api::test_support::storage::ssh::protocol::base64::decode_base64_armored;
use kapsaro_core::cli_api::test_support::storage::ssh::protocol::sshsig;
use kapsaro_core::cli_api::test_support::storage::ssh::protocol::types::Ed25519RawSignature;
use kapsaro_core::cli_api::test_support::storage::ssh::protocol::wire::decode_ssh_string;
use kapsaro_core::Result;
use std::fs;
use std::path::Path;

/// Test-only SignatureBackend that signs directly with Ed25519
///
/// Parses an OpenSSH Ed25519 private key file and signs SSHSIG signed_data
/// in-process, eliminating the need for ssh-keygen subprocess calls.
pub struct Ed25519DirectBackend {
    signing_key: SigningKey,
}

impl Ed25519DirectBackend {
    /// Load Ed25519 private key from OpenSSH format file
    pub fn new(ssh_key_path: &Path) -> Result<Self> {
        let secret_bytes = load_ed25519_secret_key(ssh_key_path)?;
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        Ok(Self { signing_key })
    }
}

impl SignatureBackend for Ed25519DirectBackend {
    fn sign_sshsig(
        &self,
        namespace: &str,
        _ssh_pubkey: &str,
        message: &[u8],
    ) -> Result<Ed25519RawSignature> {
        let sshsig_signed_data = sshsig::build_sshsig_signed_data(message, namespace);
        let signature = self.signing_key.sign(&sshsig_signed_data);
        Ok(Ed25519RawSignature::new(signature.to_bytes()))
    }
}

fn load_ed25519_secret_key(ssh_key_path: &Path) -> Result<[u8; 32]> {
    let armored = fs::read_to_string(ssh_key_path).map_err(|e| {
        kapsaro_core::Error::build_ssh_error_with_source(
            format!("Failed to read SSH key: {}", e),
            e,
        )
    })?;
    let decoded = decode_base64_armored(&armored)?;
    parse_openssh_ed25519_secret_key(decoded.as_ref())
}

fn parse_openssh_ed25519_secret_key(data: &[u8]) -> Result<[u8; 32]> {
    const MAGIC: &[u8] = b"openssh-key-v1\0";

    let Some(mut rest) = data.strip_prefix(MAGIC) else {
        return Err(unsupported_ssh_key("missing openssh-key-v1 header"));
    };

    let (ciphername, next) = decode_ssh_string(rest)?;
    rest = next;
    let (kdfname, next) = decode_ssh_string(rest)?;
    rest = next;
    let (kdfoptions, next) = decode_ssh_string(rest)?;
    rest = next;

    if ciphername != b"none" || kdfname != b"none" || !kdfoptions.is_empty() {
        return Err(unsupported_ssh_key(
            "encrypted OpenSSH private keys are not supported in this test backend",
        ));
    }

    let key_count = decode_u32(&mut rest, "public key count")?;
    if key_count != 1 {
        return Err(unsupported_ssh_key(
            "expected exactly one key in OpenSSH private key",
        ));
    }

    let (_public_blob, next) = decode_ssh_string(rest)?;
    rest = next;
    let (private_blob, _rest) = decode_ssh_string(rest)?;
    parse_private_section(private_blob)
}

fn parse_private_section(mut data: &[u8]) -> Result<[u8; 32]> {
    let check1 = decode_u32(&mut data, "checkint")?;
    let check2 = decode_u32(&mut data, "checkint")?;
    if check1 != check2 {
        return Err(unsupported_ssh_key(
            "OpenSSH private key checkints do not match",
        ));
    }

    let (key_type, next) = decode_ssh_string(data)?;
    data = next;
    if key_type != b"ssh-ed25519" {
        return Err(unsupported_ssh_key("SSH key is not Ed25519"));
    }

    let (_public_key, next) = decode_ssh_string(data)?;
    data = next;
    let (private_key, next) = decode_ssh_string(data)?;
    data = next;

    if private_key.len() != 64 {
        return Err(unsupported_ssh_key(
            "invalid OpenSSH Ed25519 private key length",
        ));
    }

    let (_comment, _padding) = decode_ssh_string(data)?;

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&private_key[..32]);
    Ok(secret)
}

fn decode_u32(data: &mut &[u8], field_name: &str) -> Result<u32> {
    if data.len() < 4 {
        return Err(unsupported_ssh_key(format!(
            "missing {} in OpenSSH private key",
            field_name
        )));
    }
    let value = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    *data = &data[4..];
    Ok(value)
}

fn unsupported_ssh_key(message: impl Into<String>) -> kapsaro_core::Error {
    kapsaro_core::Error::build_ssh_error(message.into())
}
