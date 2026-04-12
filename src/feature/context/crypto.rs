// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Crypto context data and key validation helpers.

use ed25519_dalek::SigningKey;
use std::path::{Path, PathBuf};

use crate::feature::key::protection::encryption::decrypt_private_key;
use crate::feature::verify::private_key::verify_private_key_matches_public_key;
use crate::feature::verify::public_key::verify_public_key_with_attestation;
use crate::io::keystore::public_key_source::PublicKeySource;
use crate::io::keystore::storage::{load_private_key, load_public_key};
use crate::io::ssh::backend::SignatureBackend;
use crate::model::common::WrapItem;
use crate::model::identifiers::jwk;
use crate::model::identity::{Kid, MemberId};
use crate::model::private_key::{PrivateKey, PrivateKeyAlgorithm, PrivateKeyPlaintext};
use crate::model::verified::{DecryptionProof, VerifiedPrivateKey};
use crate::support::codec::base64_public::decode_base64url_nopad_array;
use crate::support::codec::base64_secret::decode_base64url_nopad_secret_32;
use crate::support::kid::kid_display_lossy;
use crate::support::secret::SecretArray;
use crate::{Error, Result};

pub struct LocalKeyAccess {
    keystore_root: PathBuf,
    ssh_pubkey: String,
    ssh_backend: Box<dyn SignatureBackend>,
}

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
    selected_kid_override: Option<String>,
    local_key_access: Option<LocalKeyAccess>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptionKeyInfo {
    pub kid: String,
    pub expires_at: String,
    pub used_fallback: bool,
}

pub struct DecryptionResult<T> {
    pub value: T,
    pub key_info: DecryptionKeyInfo,
}

pub(crate) struct LoadedPrivateKey {
    pub(crate) private_key: VerifiedPrivateKey,
    pub(crate) expires_at: String,
}

pub(crate) enum ResolvedDecryptionKey<'a> {
    Active {
        private_key: &'a VerifiedPrivateKey,
        info: DecryptionKeyInfo,
    },
    Fallback {
        private_key: Box<VerifiedPrivateKey>,
        info: DecryptionKeyInfo,
    },
}

impl LocalKeyAccess {
    fn new(
        keystore_root: PathBuf,
        ssh_pubkey: String,
        ssh_backend: Box<dyn SignatureBackend>,
    ) -> Self {
        Self {
            keystore_root,
            ssh_pubkey,
            ssh_backend,
        }
    }
}

impl<'a> ResolvedDecryptionKey<'a> {
    pub(crate) fn private_key(&self) -> &VerifiedPrivateKey {
        match self {
            Self::Active { private_key, .. } => private_key,
            Self::Fallback { private_key, .. } => private_key,
        }
    }

    pub(crate) fn info(&self) -> &DecryptionKeyInfo {
        match self {
            Self::Active { info, .. } => info,
            Self::Fallback { info, .. } => info,
        }
    }
}

pub(crate) fn build_signing_key(plaintext: &PrivateKeyPlaintext) -> Result<SigningKey> {
    let sig_key_bytes =
        decode_base64url_nopad_secret_32(&plaintext.keys.sig.d, "Ed25519 private key")?;
    Ok(SigningKey::from_bytes(sig_key_bytes.as_array()))
}

/// Validate an OKP key (kty, crv, d/x length).
pub fn validate_okp_key(
    kty: &str,
    crv: &str,
    expected_crv: &str,
    d: &str,
    x: &str,
    label: &str,
) -> Result<(SecretArray<32>, [u8; 32])> {
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
    let d_bytes = decode_base64url_nopad_secret_32(d, &format!("{} private key", label))?;
    let x_bytes = decode_base64url_nopad_array(x, &format!("{} public key", label))?;
    Ok((d_bytes, x_bytes))
}

/// Verify Ed25519 key pair consistency: private key must derive to the given public key.
pub fn validate_ed25519_consistency(
    sig_d_bytes: &SecretArray<32>,
    sig_x_bytes: &[u8; 32],
) -> Result<()> {
    let signing_key = SigningKey::from_bytes(sig_d_bytes.as_array());
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

pub fn build_local_key_access(
    keystore_root: PathBuf,
    ssh_pubkey: String,
    ssh_backend: Box<dyn SignatureBackend>,
) -> LocalKeyAccess {
    LocalKeyAccess::new(keystore_root, ssh_pubkey, ssh_backend)
}

pub(crate) fn load_verified_private_key_from_keystore(
    keystore_root: &Path,
    member_id: &str,
    kid: &str,
    backend: &dyn SignatureBackend,
    ssh_pubkey: &str,
    debug_enabled: bool,
) -> Result<LoadedPrivateKey> {
    let encrypted_private_key = load_private_key(keystore_root, member_id, kid)?;
    let public_key = load_public_key(keystore_root, member_id, kid)?;
    let verified_public_key = verify_public_key_with_attestation(&public_key, debug_enabled)?;
    verify_private_key_matches_public_key(&encrypted_private_key, verified_public_key.document())?;

    let plaintext =
        decrypt_private_key(&encrypted_private_key, backend, ssh_pubkey, debug_enabled)?;
    let private_key = validate_and_wrap_private_key_ssh(
        plaintext,
        &encrypted_private_key.protected.member_id,
        &encrypted_private_key.protected.kid,
        extract_ssh_fingerprint(&encrypted_private_key)?,
    )?;

    Ok(LoadedPrivateKey {
        private_key,
        expires_at: encrypted_private_key.protected.expires_at.clone(),
    })
}

pub(crate) fn extract_ssh_fingerprint(private_key: &PrivateKey) -> Result<&str> {
    match &private_key.protected.alg {
        PrivateKeyAlgorithm::SshSig { fpr, .. } => Ok(fpr.as_str()),
        _ => Err(Error::Crypto {
            message: "Expected SshSig algorithm for SSH-based decryption".to_string(),
            source: None,
        }),
    }
}

impl CryptoContext {
    pub fn new(
        member_id: MemberId,
        kid: Kid,
        pub_key_source: Box<dyn PublicKeySource>,
        workspace_path: Option<PathBuf>,
        private_key: VerifiedPrivateKey,
        signing_key: SigningKey,
        expires_at: String,
    ) -> Self {
        Self {
            member_id,
            kid,
            pub_key_source,
            workspace_path,
            private_key,
            signing_key,
            expires_at,
            selected_kid_override: None,
            local_key_access: None,
        }
    }

    pub fn with_local_key_access(
        mut self,
        selected_kid_override: Option<String>,
        local_key_access: Option<LocalKeyAccess>,
    ) -> Self {
        self.selected_kid_override = selected_kid_override;
        self.local_key_access = local_key_access;
        self
    }

    pub(crate) fn select_local_decryption_key<'a>(
        &'a self,
        wrap_items: &[WrapItem],
        member_id: &str,
        debug_enabled: bool,
    ) -> Result<ResolvedDecryptionKey<'a>> {
        let wrap_kids = collect_self_wrap_kids(wrap_items, member_id);
        let candidates =
            build_candidate_kids(&wrap_kids, self.selected_kid_override.as_deref(), &self.kid);

        for kid in &candidates {
            if kid == self.kid.as_ref() {
                return Ok(ResolvedDecryptionKey::Active {
                    private_key: &self.private_key,
                    info: DecryptionKeyInfo {
                        kid: kid.clone(),
                        expires_at: self.expires_at.clone(),
                        used_fallback: false,
                    },
                });
            }

            let Some(local_key_access) = self.local_key_access.as_ref() else {
                continue;
            };

            match load_verified_private_key_from_keystore(
                &local_key_access.keystore_root,
                member_id,
                kid,
                local_key_access.ssh_backend.as_ref(),
                &local_key_access.ssh_pubkey,
                debug_enabled,
            ) {
                Ok(loaded) => {
                    return Ok(ResolvedDecryptionKey::Fallback {
                        private_key: Box::new(loaded.private_key),
                        info: DecryptionKeyInfo {
                            kid: kid.clone(),
                            expires_at: loaded.expires_at,
                            used_fallback: true,
                        },
                    });
                }
                Err(Error::NotFound { .. }) => continue,
                Err(error) => return Err(error),
            }
        }

        Err(build_missing_wrap_error(
            member_id,
            self.selected_kid_override.as_deref(),
            &candidates,
        ))
    }
}

fn collect_self_wrap_kids(wrap_items: &[WrapItem], member_id: &str) -> Vec<String> {
    let mut kids = Vec::new();
    for wrap_item in wrap_items {
        if wrap_item.rid != member_id || kids.contains(&wrap_item.kid) {
            continue;
        }
        kids.push(wrap_item.kid.clone());
    }
    kids
}

fn build_candidate_kids(
    wrap_kids: &[String],
    explicit_kid: Option<&str>,
    active_kid: &Kid,
) -> Vec<String> {
    if let Some(kid) = explicit_kid {
        return vec![kid.to_string()];
    }

    let mut candidates = Vec::new();
    if wrap_kids.iter().any(|kid| kid == active_kid.as_ref()) {
        candidates.push(active_kid.to_string());
    }
    for kid in wrap_kids {
        if candidates.contains(kid) {
            continue;
        }
        candidates.push(kid.clone());
    }
    candidates
}

fn build_missing_wrap_error(
    member_id: &str,
    explicit_kid: Option<&str>,
    searched_kids: &[String],
) -> Error {
    match explicit_kid {
        Some(kid) => Error::Crypto {
            message: format!(
                "No wrap found for kid '{}' (member: {})",
                kid_display_lossy(kid),
                member_id
            ),
            source: None,
        },
        None => {
            let searched = searched_kids
                .iter()
                .map(|kid| kid_display_lossy(kid))
                .collect::<Vec<_>>()
                .join(", ");
            Error::Crypto {
                message: format!(
                    "No wrap found for any local kid [{}] (member: {})",
                    searched, member_id
                ),
                source: None,
            }
        }
    }
}
