// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::blob::SshsigBlob;
use super::signature::Ed25519RawSignature;
use crate::Result;

/// SSHSIG armored format (Base64-encoded SSHSIG)
///
/// Format: Base64-encoded SSHSIG blob with BEGIN/END markers
/// This is the format output by `ssh-keygen -Y sign`.
#[derive(Debug, Clone)]
pub struct SshsigArmored(String);

impl SshsigArmored {
    pub fn new(armored: String) -> Self {
        Self(armored)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn extract_blob(&self) -> Result<SshsigBlob> {
        use crate::io::ssh::protocol::base64::decode_base64_armored;
        let blob = decode_base64_armored(self.as_str())?;
        Ok(SshsigBlob::new(blob))
    }

    pub fn extract_ed25519_raw(&self) -> Result<Ed25519RawSignature> {
        let blob = self.extract_blob()?;
        blob.extract_ed25519_raw()
    }
}
