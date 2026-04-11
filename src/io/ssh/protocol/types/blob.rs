// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::signature::Ed25519RawSignature;
use crate::io::ssh::protocol::constants as ssh;
use crate::io::ssh::protocol::sshsig::parse_sshsig_blob;
use crate::io::ssh::protocol::wire::ssh_string_decode;
use crate::io::ssh::SshError;
use crate::Result;
use zeroize::Zeroizing;

/// SSH signature blob (SSH wire format)
///
/// Format: `string algorithm` + `string signature`
/// This is the format returned by SSHSIG parsing and used in SSH protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshSignatureBlob(Vec<u8>);

impl SshSignatureBlob {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn extract_ed25519_raw(&self) -> Result<Ed25519RawSignature> {
        if self.0.len() == 64 {
            let mut out = Zeroizing::new([0u8; 64]);
            out.as_mut().copy_from_slice(&self.0);
            return Ok(Ed25519RawSignature::from_zeroizing(out));
        }

        let (algo, rest) = ssh_string_decode(&self.0)?;
        if algo != ssh::KEY_TYPE_ED25519.as_bytes() {
            return Err(SshError::operation_failed(format!(
                "Unsupported SSH signature algorithm '{}': expected '{}'",
                String::from_utf8_lossy(algo),
                ssh::KEY_TYPE_ED25519
            ))
            .into());
        }

        let (sig, rest) = ssh_string_decode(rest)?;
        if !rest.is_empty() {
            return Err(
                SshError::operation_failed("Invalid SSH signature blob: trailing bytes").into(),
            );
        }
        if sig.len() != 64 {
            return Err(SshError::operation_failed(format!(
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

/// SSHSIG blob (complete SSHSIG format)
#[derive(Debug, Clone)]
pub struct SshsigBlob(Vec<u8>);

impl SshsigBlob {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn extract_signature_blob(&self) -> Result<SshSignatureBlob> {
        parse_sshsig_blob(self.as_bytes())
    }

    pub fn extract_ed25519_raw(&self) -> Result<Ed25519RawSignature> {
        let sig_blob = self.extract_signature_blob()?;
        sig_blob.extract_ed25519_raw()
    }
}
