// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH fingerprint computation (pure functions).

use super::parse::decode_ssh_public_key_blob;
use crate::support::codec::base64_public::encode_base64_standard_nopad;
use crate::Result;
use sha2::{Digest, Sha256};

/// Calculate OpenSSH SHA256 fingerprint from an ed25519 public key line.
/// Input: `ssh-ed25519 <base64_blob> [comment]` -> Output: `SHA256:<base64_no_pad>`
pub fn build_sha256_fingerprint(ssh_pubkey: &str) -> Result<String> {
    let key_blob = decode_ssh_public_key_blob(ssh_pubkey)?;
    let hash = Sha256::digest(&key_blob);
    let b64_no_pad = encode_base64_standard_nopad(hash.as_ref());
    Ok(format!("SHA256:{}", b64_no_pad))
}
