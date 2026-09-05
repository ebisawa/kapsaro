// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Password-protected key loading for caller-supplied CI credentials.
//! Decodes and validates explicit secret values without reading process state.

use crate::feature::context::crypto::build_verified_private_key_from_password;
use crate::feature::context::expiry::VerifiedExpiresAt;
use crate::feature::key::protection::password_encryption::decrypt_private_key_with_password;
use crate::format::codec::base64_secret::decode_base64url_nopad_secret_bytes;
use crate::format::schema::document::parse_private_key_bytes;
use crate::model::identity::MemberHandle;
use crate::model::private_key::{PrivateKey, PrivateKeyAlgorithm};
use crate::model::verified::VerifiedPrivateKey;
use crate::model::wire::private_key::PROTECTION_KDF_ARGON2ID_M64T3P4_HKDF_SHA256;
use crate::support::kid::format_kid_half_display_lossy;
use crate::support::secret::{SecretBytes, SecretString};
use crate::{Error, Result};
use tracing::debug;

const PRIVATE_KEY_SOURCE: &str = "provided private key";

/// Result of parsing a caller-supplied encoded private key
#[derive(Debug)]
pub struct EnvKeyParseResult {
    pub verified_key: VerifiedPrivateKey,
    pub member_handle: MemberHandle,
    pub expires_at: VerifiedExpiresAt,
}

/// Decode and verify one password-protected key supplied by the caller.
pub(crate) fn parse_env_key(
    encoded: SecretString,
    password: SecretString,
) -> Result<EnvKeyParseResult> {
    let json_bytes = decode_private_key_env(encoded.as_str())?;
    debug!("[ENV_KEY] load private key: decoded private key payload");
    let private_key = parse_password_protected_private_key(json_bytes.as_bytes())?;
    debug!(
        "[ENV_KEY] load private key: parsed password-protected key member_handle={}, kid={}",
        private_key.protected.subject_handle,
        format_kid_half_display_lossy(&private_key.protected.kid)
    );
    build_env_key_parse_result(&private_key, &password)
}

fn decode_private_key_env(encoded: &str) -> Result<SecretBytes> {
    decode_base64url_nopad_secret_bytes(encoded, PRIVATE_KEY_SOURCE)
}

fn parse_password_protected_private_key(json_bytes: &[u8]) -> Result<PrivateKey> {
    let private_key: PrivateKey = parse_private_key_bytes(json_bytes, PRIVATE_KEY_SOURCE)?;
    match &private_key.protected.alg {
        PrivateKeyAlgorithm::Argon2id { .. } => Ok(private_key),
        _ => Err(Error::build_config_error(format!(
            "{} must contain a password-protected key ({})",
            PRIVATE_KEY_SOURCE, PROTECTION_KDF_ARGON2ID_M64T3P4_HKDF_SHA256
        ))),
    }
}

fn build_env_key_parse_result(
    private_key: &PrivateKey,
    password: &SecretString,
) -> Result<EnvKeyParseResult> {
    let member_handle = private_key.protected.subject_handle.clone();
    let kid = private_key.protected.kid.clone();
    let plaintext = decrypt_private_key_with_password(private_key, password)?;
    let verified_key = build_verified_private_key_from_password(plaintext, &member_handle, &kid)?;
    debug!(
        "[ENV_KEY] load private key: complete member_handle={}, kid={}",
        member_handle,
        format_kid_half_display_lossy(&kid)
    );

    Ok(EnvKeyParseResult {
        verified_key,
        member_handle: MemberHandle::try_from(member_handle)?,
        expires_at: VerifiedExpiresAt::from_verified_private_key_metadata(
            private_key.protected.expires_at.clone(),
        ),
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_context_env_key_test.rs"]
mod feature_context_env_key_test;
