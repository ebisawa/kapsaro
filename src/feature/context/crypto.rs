// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Crypto context data and key validation helpers.

use ed25519_dalek::SigningKey;
use std::path::PathBuf;
use zeroize::Zeroizing;

use crate::io::keystore::public_key_source::PublicKeySource;
use crate::model::identifiers::jwk;
use crate::model::identity::{Kid, MemberId};
use crate::model::private_key::PrivateKeyPlaintext;
use crate::model::verified::{DecryptionProof, VerifiedPrivateKey};
use crate::support::base64url::{b64_decode, b64_decode_secret_array};
use crate::{Error, Result};

/// Context for cryptographic operations requiring member keys
pub struct CryptoContext {
    pub member_id: MemberId,
    pub kid: Kid,
    pub pub_key_source: Box<dyn PublicKeySource>,
    pub workspace_path: Option<PathBuf>,
    pub private_key: VerifiedPrivateKey,
    pub signing_key: SigningKey,
    /// Key expiration timestamp (RFC 3339) from PrivateKeyProtected
    pub expires_at: String,
}

pub(crate) fn build_signing_key(plaintext: &PrivateKeyPlaintext) -> Result<SigningKey> {
    let sig_key_bytes = b64_decode_secret_array(&plaintext.keys.sig.d, "Ed25519 private key")?;
    Ok(SigningKey::from_bytes(&sig_key_bytes))
}

/// Validate an OKP key (kty, crv, d/x length).
pub fn validate_okp_key(
    kty: &str,
    crv: &str,
    expected_crv: &str,
    d: &str,
    x: &str,
    label: &str,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    if kty != "OKP" {
        return Err(Error::Crypto {
            message: format!("Invalid {} key type: expected 'OKP', got '{}'", label, kty),
            source: None,
        });
    }
    if crv != expected_crv {
        return Err(Error::Crypto {
            message: format!(
                "Invalid {} curve: expected '{}', got '{}'",
                label, expected_crv, crv
            ),
            source: None,
        });
    }
    let d_bytes = Zeroizing::new(b64_decode(d, &format!("{} private key", label))?);
    let x_bytes = b64_decode(x, &format!("{} public key", label))?;
    if d_bytes.len() != 32 {
        return Err(Error::Crypto {
            message: format!(
                "Invalid {} private key length: expected 32 bytes, got {}",
                label,
                d_bytes.len()
            ),
            source: None,
        });
    }
    if x_bytes.len() != 32 {
        return Err(Error::Crypto {
            message: format!(
                "Invalid {} public key length: expected 32 bytes, got {}",
                label,
                x_bytes.len()
            ),
            source: None,
        });
    }
    Ok((d_bytes, x_bytes))
}

/// Verify Ed25519 key pair consistency: private key must derive to the given public key.
pub fn validate_ed25519_consistency(sig_d_bytes: &[u8], sig_x_bytes: &[u8]) -> Result<()> {
    if sig_d_bytes.len() != 32 {
        return Err(Error::Crypto {
            message: "Failed to convert Sig private key to array".to_string(),
            source: None,
        });
    }

    let mut sig_d_array = Zeroizing::new([0u8; 32]);
    sig_d_array.as_mut().copy_from_slice(sig_d_bytes);
    let signing_key = SigningKey::from_bytes(&sig_d_array);
    let derived_vk = signing_key.verifying_key();
    let derived_x_bytes = derived_vk.as_bytes();
    if derived_x_bytes != sig_x_bytes {
        return Err(Error::Crypto {
            message: "Ed25519 key pair inconsistency: private key does not derive to public key"
                .to_string(),
            source: None,
        });
    }
    Ok(())
}

/// Validate private key plaintext and wrap in Decrypted type (SSH-based decryption)
pub(crate) fn validate_and_wrap_private_key_ssh(
    plaintext: PrivateKeyPlaintext,
    member_id: &str,
    kid: &str,
    ssh_fpr: &str,
) -> Result<VerifiedPrivateKey> {
    validate_private_key_material(&plaintext)?;

    let proof = DecryptionProof {
        member_id: member_id.to_string(),
        kid: kid.to_string(),
        ssh_fpr: Some(ssh_fpr.to_string()),
    };
    Ok(VerifiedPrivateKey::new(plaintext, proof))
}

/// Validate private key plaintext and wrap in Decrypted type (password-based decryption)
pub fn validate_and_wrap_private_key_password(
    plaintext: PrivateKeyPlaintext,
    member_id: &str,
    kid: &str,
) -> Result<VerifiedPrivateKey> {
    validate_private_key_material(&plaintext)?;

    let proof = DecryptionProof {
        member_id: member_id.to_string(),
        kid: kid.to_string(),
        ssh_fpr: None,
    };
    Ok(VerifiedPrivateKey::new(plaintext, proof))
}

/// Validate private key material (OKP structure and Ed25519 consistency)
pub(crate) fn validate_private_key_material(plaintext: &PrivateKeyPlaintext) -> Result<()> {
    let kem = &plaintext.keys.kem;
    validate_okp_key(&kem.kty, &kem.crv, jwk::CRV_X25519, &kem.d, &kem.x, "KEM")?;

    let sig = &plaintext.keys.sig;
    let (sig_d_bytes, sig_x_bytes) =
        validate_okp_key(&sig.kty, &sig.crv, jwk::CRV_ED25519, &sig.d, &sig.x, "Sig")?;
    validate_ed25519_consistency(&sig_d_bytes, &sig_x_bytes)?;

    Ok(())
}
