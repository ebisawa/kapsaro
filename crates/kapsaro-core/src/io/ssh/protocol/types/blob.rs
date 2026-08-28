// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Wire blobs carried by the SSH signing protocol.
//! Keeps the bytes zeroized and hands out only what a caller has validated.

use super::signature::Ed25519RawSignature;
use crate::io::ssh::protocol::constants as ssh;
use crate::io::ssh::protocol::wire::decode_ssh_string;
use crate::io::ssh::SshError;
use crate::Result;
use zeroize::Zeroizing;

/// Byte length of a raw Ed25519 signature.
const ED25519_SIGNATURE_LENGTH: usize = 64;

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

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn extract_ed25519_raw(&self) -> Result<Ed25519RawSignature> {
        // A bare signature carries no wire framing to decode.
        let signature = if self.0.len() == ED25519_SIGNATURE_LENGTH {
            self.0.as_slice()
        } else {
            decode_ed25519_wire_signature(&self.0)?
        };
        Ok(to_raw_ed25519_signature(signature))
    }
}

/// Decode `string algorithm` + `string signature` into the signature bytes.
fn decode_ed25519_wire_signature(blob: &[u8]) -> Result<&[u8]> {
    let (algo, rest) = decode_ssh_string(blob)?;
    if algo != ssh::KEY_TYPE_ED25519.as_bytes() {
        return Err(SshError::build_operation_failed_error(format!(
            "Unsupported SSH signature algorithm '{}': expected '{}'",
            String::from_utf8_lossy(algo),
            ssh::KEY_TYPE_ED25519
        ))
        .into());
    }

    let (signature, rest) = decode_ssh_string(rest)?;
    if !rest.is_empty() {
        return Err(SshError::build_operation_failed_error(
            "Invalid SSH signature blob: trailing bytes",
        )
        .into());
    }
    if signature.len() != ED25519_SIGNATURE_LENGTH {
        return Err(SshError::build_operation_failed_error(format!(
            "Invalid Ed25519 signature length: expected {} bytes, got {}",
            ED25519_SIGNATURE_LENGTH,
            signature.len()
        ))
        .into());
    }

    Ok(signature)
}

fn to_raw_ed25519_signature(signature: &[u8]) -> Ed25519RawSignature {
    let mut out = Zeroizing::new([0u8; ED25519_SIGNATURE_LENGTH]);
    out.as_mut().copy_from_slice(signature);
    Ed25519RawSignature::from_zeroizing(out)
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
