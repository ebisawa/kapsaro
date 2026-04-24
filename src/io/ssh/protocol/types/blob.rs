// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::signature::Ed25519RawSignature;
use crate::io::ssh::protocol::constants as ssh;
use crate::io::ssh::protocol::sshsig::parse_sshsig_blob;
use crate::io::ssh::protocol::wire::decode_ssh_string;
use crate::io::ssh::SshError;
use crate::Result;
use zeroize::Zeroizing;

/// SSH signature blob (SSH wire format)
///
/// Format: `string algorithm` + `string signature`
/// This is the format returned by SSHSIG parsing and used in SSH protocol.
#[derive(Clone)]
pub struct SshSignatureBlob(Zeroizing<Vec<u8>>);

impl SshSignatureBlob {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn from_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn extract_ed25519_raw(&self) -> Result<Ed25519RawSignature> {
        if self.0.len() == 64 {
            let mut out = Zeroizing::new([0u8; 64]);
            out.as_mut().copy_from_slice(&self.0);
            return Ok(Ed25519RawSignature::from_zeroizing(out));
        }

        let (algo, rest) = decode_ssh_string(&self.0)?;
        if algo != ssh::KEY_TYPE_ED25519.as_bytes() {
            return Err(SshError::build_operation_failed_error(format!(
                "Unsupported SSH signature algorithm '{}': expected '{}'",
                String::from_utf8_lossy(algo),
                ssh::KEY_TYPE_ED25519
            ))
            .into());
        }

        let (sig, rest) = decode_ssh_string(rest)?;
        if !rest.is_empty() {
            return Err(SshError::build_operation_failed_error(
                "Invalid SSH signature blob: trailing bytes",
            )
            .into());
        }
        if sig.len() != 64 {
            return Err(SshError::build_operation_failed_error(format!(
                "Invalid Ed25519 signature length: expected 64 bytes, got {}",
                sig.len()
            ))
            .into());
        }

        let mut out = Zeroizing::new([0u8; 64]);
        out.as_mut().copy_from_slice(sig);
        Ok(Ed25519RawSignature::from_zeroizing(out))
    }
}

impl PartialEq for SshSignatureBlob {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for SshSignatureBlob {}

impl std::fmt::Debug for SshSignatureBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SshSignatureBlob([REDACTED])")
    }
}

/// SSHSIG blob (complete SSHSIG format)
#[derive(Clone)]
pub struct SshsigBlob(Zeroizing<Vec<u8>>);

impl SshsigBlob {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn from_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn extract_signature_blob(&self, expected_namespace: &str) -> Result<SshSignatureBlob> {
        parse_sshsig_blob(self.as_bytes(), expected_namespace)
    }

    pub fn extract_ed25519_raw(&self, expected_namespace: &str) -> Result<Ed25519RawSignature> {
        let sig_blob = self.extract_signature_blob(expected_namespace)?;
        sig_blob.extract_ed25519_raw()
    }
}

impl std::fmt::Debug for SshsigBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SshsigBlob([REDACTED])")
    }
}
