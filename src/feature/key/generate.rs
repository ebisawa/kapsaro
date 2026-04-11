// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key generation logic.

use crate::feature::key::protection::encryption::{
    encrypt_private_key, PrivateKeyEncryptionParams,
};
use crate::feature::key::ssh_binding::SshBindingContext;
use crate::feature::key::types::KeyNewResult;
use crate::feature::key::{material, public_key_document};
use crate::io::keystore::active::set_active_kid;
use crate::io::keystore::resolver::KeystoreResolver;
use crate::io::keystore::storage::{find_member_by_kid, save_key_pair_atomic};
use crate::model::private_key::PrivateKey;
use crate::model::public_key::{GithubAccount, Identity, PublicKey};
use crate::model::ssh::SshDeterminismStatus;
use crate::support::kid::kid_display_lossy;
use crate::Error;
use crate::Result;
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

/// Options for key generation.
pub struct KeyGenerationOptions {
    pub member_id: String,
    pub home: Option<PathBuf>,
    pub created_at: String,
    pub expires_at: String,
    pub no_activate: bool,
    pub debug: bool,
    pub github_account: Option<GithubAccount>,
    pub verbose: bool,
    /// Pre-resolved SSH signing context.
    pub ssh_binding: SshBindingContext,
}

struct GeneratedKeyMaterial {
    kem_sk: X25519SecretKey,
    kem_pk: X25519PublicKey,
    sig_sk: SigningKey,
    sig_pk: VerifyingKey,
}

struct KeyDocumentBuildRequest<'a> {
    member_id: &'a str,
    created_at: &'a str,
    expires_at: &'a str,
    github_account: Option<GithubAccount>,
    debug: bool,
}

/// Generate a new key pair and save to keystore.
pub fn generate_key(opts: KeyGenerationOptions) -> Result<KeyNewResult> {
    let KeyGenerationOptions {
        member_id,
        home,
        created_at,
        expires_at,
        no_activate,
        debug,
        github_account,
        verbose: _,
        ssh_binding,
    } = opts;

    let keystore_root = ensure_keystore_dir(&home)?;
    ensure_determinism(&ssh_binding.determinism)?;
    let key_material = generate_key_material()?;
    let request = KeyDocumentBuildRequest {
        member_id: &member_id,
        created_at: &created_at,
        expires_at: &expires_at,
        github_account,
        debug,
    };
    let public_key = build_public_key_document(&request, &key_material, &ssh_binding)?;
    let derived_kid = public_key.protected.kid.clone();
    ensure_kid_not_in_keystore(&keystore_root, &derived_kid)?;
    let private_key =
        encrypt_private_key_document(&request, &key_material, &derived_kid, &ssh_binding)?;
    save_generated_key(
        &keystore_root,
        &member_id,
        &derived_kid,
        &private_key,
        &public_key,
        no_activate,
    )?;

    let key_dir = keystore_root.join(&member_id).join(&derived_kid);
    Ok(KeyNewResult {
        member_id,
        kid: derived_kid,
        created_at,
        expires_at,
        keystore_root,
        key_dir,
        activated: !no_activate,
        ssh_fingerprint: ssh_binding.fingerprint,
        ssh_public_key: ssh_binding.public_key,
        ssh_determinism: ssh_binding.determinism,
    })
}

fn ensure_kid_not_in_keystore(keystore_root: &Path, kid: &str) -> Result<()> {
    match find_member_by_kid(keystore_root, kid) {
        Ok(owner_member_id) => Err(Error::Crypto {
            message: format!(
                "kid '{}' already exists in keystore (member_id: '{}')",
                kid_display_lossy(kid),
                owner_member_id
            ),
            source: None,
        }),
        Err(Error::NotFound { .. }) => Ok(()),
        Err(e) => Err(e),
    }
}

fn generate_key_material() -> Result<GeneratedKeyMaterial> {
    let keypairs = material::generate_keypairs()?;
    Ok(GeneratedKeyMaterial {
        kem_sk: keypairs.kem_sk,
        kem_pk: keypairs.kem_pk,
        sig_sk: keypairs.sig_sk,
        sig_pk: keypairs.sig_pk,
    })
}

fn ensure_determinism(status: &SshDeterminismStatus) -> Result<()> {
    match status {
        SshDeterminismStatus::Verified => Ok(()),
        SshDeterminismStatus::Skipped => Err(crate::Error::Crypto {
            message: "SSH determinism check was not performed; key generation requires it".into(),
            source: None,
        }),
        SshDeterminismStatus::Failed { message } => Err(crate::Error::Crypto {
            message: message.clone(),
            source: None,
        }),
    }
}

fn build_public_key_document(
    request: &KeyDocumentBuildRequest<'_>,
    key_material: &GeneratedKeyMaterial,
    ssh_binding: &SshBindingContext,
) -> Result<PublicKey> {
    let identity_keys = material::build_identity_keys(&key_material.kem_pk, &key_material.sig_pk)?;
    let attestation = public_key_document::build_attestation(ssh_binding, &identity_keys)?;
    let identity = Identity {
        keys: identity_keys,
        attestation,
    };
    public_key_document::build_public_key(&public_key_document::PublicKeyBuildParams {
        member_id: request.member_id,
        identity,
        created_at: request.created_at,
        expires_at: request.expires_at,
        sig_sk: &key_material.sig_sk,
        debug: request.debug,
        github_account: request.github_account.clone(),
    })
}

fn encrypt_private_key_document(
    request: &KeyDocumentBuildRequest<'_>,
    key_material: &GeneratedKeyMaterial,
    derived_kid: &str,
    ssh_binding: &SshBindingContext,
) -> Result<PrivateKey> {
    let plaintext = material::build_private_key_plaintext(
        &key_material.kem_sk,
        &key_material.kem_pk,
        &key_material.sig_sk,
        &key_material.sig_pk,
    );
    encrypt_private_key(&PrivateKeyEncryptionParams {
        plaintext: &plaintext,
        member_id: request.member_id.to_string(),
        kid: derived_kid.to_string(),
        backend: ssh_binding.backend.as_ref(),
        ssh_pubkey: &ssh_binding.public_key,
        ssh_fpr: ssh_binding.fingerprint.clone(),
        created_at: request.created_at.to_string(),
        expires_at: request.expires_at.to_string(),
        debug: request.debug,
    })
}

/// Ensure keystore directory exists.
pub(crate) fn ensure_keystore_dir(home: &Option<PathBuf>) -> Result<PathBuf> {
    KeystoreResolver::resolve_and_ensure(home.as_ref())
}

fn save_generated_key(
    keystore_root: &Path,
    member_id: &str,
    kid: &str,
    private_key: &PrivateKey,
    public_key: &PublicKey,
    no_activate: bool,
) -> Result<()> {
    save_key_pair_atomic(keystore_root, member_id, kid, private_key, public_key)?;
    if !no_activate {
        set_active_kid(member_id, kid, keystore_root)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/unit/feature_key_generate_internal_test.rs"]
mod tests;
