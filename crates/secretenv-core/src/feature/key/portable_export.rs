// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Portable private key export with password-based encryption.
//!
//! Re-encrypts a decrypted private key with a user-supplied password,
//! then JCS-normalizes and Base64url-encodes the result for portable transport.

use crate::feature::key::protection::password_encryption::encrypt_private_key_with_password;
use crate::format::jcs;
use crate::model::private_key::PrivateKeyPlaintext;
use crate::support::codec::base64_secret::encode_base64url_nopad_secret_bytes;
use crate::support::secret::SecretBytes;
use crate::support::secret::SecretString;
use crate::{Error, Result};

/// Output of a portable private key export operation.
pub(crate) struct PortableExportOutput {
    pub(crate) member_handle: String,
    pub(crate) kid: String,
    pub(crate) encoded_key: SecretString,
    pub(crate) password_warning: Option<String>,
}

const MIN_PASSWORD_LENGTH: usize = 8;
const RECOMMENDED_PASSWORD_LENGTH: usize = 20;

/// Export a private key as a portable, password-protected Base64url string.
///
/// The result is a Base64url-encoded (no padding) JCS-normalized JSON document
/// containing the password-encrypted private key.
pub fn export_private_key_portable(
    plaintext: &PrivateKeyPlaintext,
    member_handle: &str,
    kid: &str,
    created_at: &str,
    expires_at: &str,
    password: &SecretString,
    debug: bool,
) -> Result<SecretString> {
    validate_password_length(password.as_str())?;

    let private_key = encrypt_private_key_with_password(
        plaintext,
        member_handle,
        kid,
        created_at,
        expires_at,
        password,
        debug,
    )?;

    let jcs_bytes = SecretBytes::new(jcs::normalize(&private_key)?);
    Ok(encode_base64url_nopad_secret_bytes(&jcs_bytes))
}

/// Validate that the password meets minimum length requirements.
fn validate_password_length(password: &str) -> Result<()> {
    if password.len() < MIN_PASSWORD_LENGTH {
        return Err(Error::build_invalid_argument_error(format!(
            "Password must be at least {} bytes",
            MIN_PASSWORD_LENGTH
        )));
    }
    Ok(())
}

/// Build a non-fatal warning for accepted passwords below the recommended length.
pub fn build_password_strength_warning(password: &str) -> Option<String> {
    if password.len() < MIN_PASSWORD_LENGTH || password.len() >= RECOMMENDED_PASSWORD_LENGTH {
        return None;
    }

    Some(format!(
        "Password accepted, but it is shorter than the recommended {} bytes for offline brute-force resistance.",
        RECOMMENDED_PASSWORD_LENGTH
    ))
}
