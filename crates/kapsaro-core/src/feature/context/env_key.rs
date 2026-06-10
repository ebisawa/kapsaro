// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Environment variable key loading for CI environments
//!
//! Loads private keys from KAPSARO_PRIVATE_KEY environment variable,
//! decrypts using KAPSARO_KEY_PASSWORD, and validates the key material.

use crate::feature::context::crypto::build_verified_private_key_from_password;
use crate::feature::context::expiry::VerifiedExpiresAt;
use crate::feature::key::protection::password_encryption::decrypt_private_key_with_password;
use crate::format::codec::base64_secret::decode_base64url_nopad_secret_bytes;
use crate::format::schema::document::parse_private_key_bytes;
use crate::model::identity::MemberHandle;
use crate::model::private_key::{PrivateKey, PrivateKeyAlgorithm};
use crate::model::verified::VerifiedPrivateKey;
use crate::support::kid::format_kid_half_display_lossy;
use crate::support::secret::{SecretBytes, SecretString};
use crate::{Error, Result};
use tracing::debug;

const ENV_PRIVATE_KEY: &str = "KAPSARO_PRIVATE_KEY";
const ENV_KEY_PASSWORD: &str = "KAPSARO_KEY_PASSWORD";

struct EnvKeyCleanupGuard {
    debug_enabled: bool,
}

impl Drop for EnvKeyCleanupGuard {
    fn drop(&mut self) {
        // TODO(edition-2024): wrap in unsafe {} with SAFETY comment:
        // called from main thread only, no concurrent env access.
        std::env::remove_var(ENV_PRIVATE_KEY);
        std::env::remove_var(ENV_KEY_PASSWORD);
        if self.debug_enabled {
            debug!("[ENV_KEY] cleanup private key environment");
        }
    }
}

/// Check if environment variable key mode is active
pub fn is_env_key_mode() -> bool {
    std::env::var_os(ENV_PRIVATE_KEY).is_some()
}

/// Result of loading a private key from environment variables
#[derive(Debug)]
pub struct EnvKeyLoadResult {
    pub verified_key: VerifiedPrivateKey,
    pub member_handle: MemberHandle,
    pub expires_at: VerifiedExpiresAt,
}

/// Load private key from environment variables
///
/// Reads KAPSARO_PRIVATE_KEY (Base64url-encoded PrivateKey JSON),
/// decrypts it using KAPSARO_KEY_PASSWORD, and validates the key material.
/// This path intentionally does not resolve the caller's own PublicKey
/// from the workspace during key loading.
pub fn load_private_key_from_env(debug: bool) -> Result<EnvKeyLoadResult> {
    // Safety: clear sensitive env vars on every exit path.
    // This is intentional security hygiene to minimize secret exposure.
    // Note: std::env::remove_var is not thread-safe; this function must
    // be called from the main thread only. The env vars cannot be
    // recovered after removal, so retries require re-setting them.
    if debug {
        debug!("[ENV_KEY] load private key: start");
    }
    let _cleanup = EnvKeyCleanupGuard {
        debug_enabled: debug,
    };
    let encoded = load_env_private_key()?;
    if debug {
        debug!("[ENV_KEY] load private key: private key env present");
    }
    let password = load_env_key_password()?;
    if debug {
        debug!("[ENV_KEY] load private key: password env present");
    }
    let json_bytes = decode_private_key_env(encoded.as_str())?;
    if debug {
        debug!("[ENV_KEY] load private key: decoded private key payload");
    }
    let private_key = parse_password_protected_private_key(json_bytes.as_bytes())?;
    if debug {
        debug!(
            "[ENV_KEY] load private key: parsed password-protected key member_handle={}, kid={}",
            private_key.protected.subject_handle,
            format_kid_half_display_lossy(&private_key.protected.kid)
        );
    }
    build_env_key_load_result(&private_key, &password, debug)
}

fn load_env_private_key() -> Result<SecretString> {
    Ok(SecretString::new(std::env::var(ENV_PRIVATE_KEY).map_err(
        |e| match e {
            std::env::VarError::NotPresent => Error::build_config_error(format!(
                "{} environment variable is not set",
                ENV_PRIVATE_KEY
            )),
            std::env::VarError::NotUnicode(_) => Error::build_config_error(format!(
                "{} environment variable contains invalid UTF-8",
                ENV_PRIVATE_KEY
            )),
        },
    )?))
}

fn load_env_key_password() -> Result<SecretString> {
    Ok(SecretString::new(std::env::var(ENV_KEY_PASSWORD).map_err(
        |e| match e {
            std::env::VarError::NotPresent => Error::build_config_error(format!(
                "{} environment variable is required when {} is set",
                ENV_KEY_PASSWORD, ENV_PRIVATE_KEY
            )),
            std::env::VarError::NotUnicode(_) => Error::build_config_error(format!(
                "{} environment variable contains invalid UTF-8",
                ENV_KEY_PASSWORD
            )),
        },
    )?))
}

fn decode_private_key_env(encoded: &str) -> Result<SecretBytes> {
    decode_base64url_nopad_secret_bytes(encoded, ENV_PRIVATE_KEY)
}

fn parse_password_protected_private_key(json_bytes: &[u8]) -> Result<PrivateKey> {
    let private_key: PrivateKey = parse_private_key_bytes(json_bytes, ENV_PRIVATE_KEY)?;
    match &private_key.protected.alg {
        PrivateKeyAlgorithm::Argon2id { .. } => Ok(private_key),
        _ => Err(Error::build_config_error(format!(
            "{} must contain a password-protected key (argon2id-m64t3p4-hkdf-sha256)",
            ENV_PRIVATE_KEY
        ))),
    }
}

fn build_env_key_load_result(
    private_key: &PrivateKey,
    password: &SecretString,
    debug: bool,
) -> Result<EnvKeyLoadResult> {
    let member_handle = private_key.protected.subject_handle.clone();
    let kid = private_key.protected.kid.clone();
    let plaintext = decrypt_private_key_with_password(private_key, password, debug)?;
    let verified_key = build_verified_private_key_from_password(plaintext, &member_handle, &kid)?;
    if debug {
        debug!(
            "[ENV_KEY] load private key: complete member_handle={}, kid={}",
            member_handle,
            format_kid_half_display_lossy(&kid)
        );
    }

    Ok(EnvKeyLoadResult {
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
