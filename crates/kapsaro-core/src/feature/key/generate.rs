// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key generation logic.

use crate::feature::key::protection::encryption::{
    encrypt_private_key, PrivateKeyEncryptionParams,
};
use crate::feature::key::ssh_binding::SshBindingContext;
use crate::feature::key::types::KeyGenerationResult;
use crate::feature::key::{material, public_key_document};
use crate::format::public_key::AttestationBodyInput;
use crate::model::private_key::PrivateKey;
use crate::model::public_key::{GithubAccount, PublicKey};
use crate::model::ssh::SshDeterminismStatus;
use crate::support::kid::format_kid_display_lossy;
use crate::Result;
use tracing::debug;

/// Options for key generation.
pub struct KeyGenerationOptions {
    pub member_handle: String,
    pub created_at: String,
    pub expires_at: String,
    pub github_account: Option<GithubAccount>,
    /// Pre-resolved SSH signing context.
    pub ssh_binding: SshBindingContext,
}

struct KeyDocumentParams<'a> {
    member_handle: &'a str,
    created_at: &'a str,
    expires_at: &'a str,
    github_account: Option<GithubAccount>,
}

/// Generate a new key pair and return unsigned persistence inputs.
pub fn generate_key(opts: KeyGenerationOptions) -> Result<KeyGenerationResult> {
    let KeyGenerationOptions {
        member_handle,
        created_at,
        expires_at,
        github_account,
        ssh_binding,
    } = opts;

    debug!(
        "[KEYGEN] start member_handle={}, github_binding={}",
        member_handle,
        github_account.is_some()
    );
    ensure_determinism(&ssh_binding.determinism)?;
    debug!("[KEYGEN] ssh determinism verified");
    let documents = build_key_documents(
        &KeyDocumentParams {
            member_handle: &member_handle,
            created_at: &created_at,
            expires_at: &expires_at,
            github_account,
        },
        &ssh_binding,
    )?;
    debug!(
        "[KEYGEN] generated key pair member_handle={}",
        member_handle
    );

    Ok(KeyGenerationResult {
        member_handle,
        kid: documents.kid,
        expires_at,
        private_key: documents.private_key,
        public_key: documents.public_key,
        ssh_fingerprint: ssh_binding.fingerprint,
        ssh_determinism: ssh_binding.determinism,
    })
}

/// The two documents one generated key pair is stored as.
struct KeyDocumentSet {
    kid: String,
    private_key: PrivateKey,
    public_key: PublicKey,
}

/// Generate the key material and write both documents that carry it.
///
/// The key id is derived from the public document and then names the private
/// one, so both are built here rather than from two separate readings of the
/// same material.
fn build_key_documents(
    request: &KeyDocumentParams<'_>,
    ssh_binding: &SshBindingContext,
) -> Result<KeyDocumentSet> {
    let key_material = material::generate_keypairs()?;
    let public_key = build_public_key_document(request, &key_material, ssh_binding)?;
    let kid = public_key.protected.kid.clone();
    debug!(
        "[KEYGEN] derived public key id kid={}",
        format_kid_display_lossy(&kid)
    );
    let private_key = encrypt_private_key_document(request, &key_material, &kid, ssh_binding)?;
    Ok(KeyDocumentSet {
        kid,
        private_key,
        public_key,
    })
}

fn ensure_determinism(status: &SshDeterminismStatus) -> Result<()> {
    match status {
        SshDeterminismStatus::Verified => Ok(()),
        SshDeterminismStatus::Skipped => Err(crate::Error::build_crypto_error(
            "SSH determinism check was not performed; key generation requires it",
        )),
        SshDeterminismStatus::Failed { message } => {
            Err(crate::Error::build_crypto_error(message.clone()))
        }
    }
}

fn build_public_key_document(
    request: &KeyDocumentParams<'_>,
    key_material: &material::KeypairMaterial,
    ssh_binding: &SshBindingContext,
) -> Result<PublicKey> {
    let keys = material::build_identity_keys(&key_material.kem_pk, &key_material.sig_pk)?;
    let binding_claims = public_key_document::build_binding_claims(request.github_account.clone());
    let attestation = public_key_document::build_attestation(
        ssh_binding,
        &AttestationBodyInput {
            subject_handle: request.member_handle,
            keys: &keys,
            binding_claims: binding_claims.as_ref(),
            created_at: Some(request.created_at),
            expires_at: request.expires_at,
        },
    )?;
    public_key_document::build_public_key(&public_key_document::PublicKeyDocumentParams {
        member_handle: request.member_handle,
        keys,
        binding_claims,
        attestation,
        created_at: request.created_at,
        expires_at: request.expires_at,
        sig_sk: &key_material.sig_sk,
    })
}

fn encrypt_private_key_document(
    request: &KeyDocumentParams<'_>,
    key_material: &material::KeypairMaterial,
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
        member_handle: request.member_handle.to_string(),
        kid: derived_kid.to_string(),
        backend: ssh_binding.backend.as_ref(),
        ssh_pubkey: &ssh_binding.public_key,
        ssh_fpr: ssh_binding.fingerprint.clone(),
        created_at: request.created_at.to_string(),
        expires_at: request.expires_at.to_string(),
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_key_generate_internal_test.rs"]
mod feature_key_generate_internal_test;

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_key_generate_test.rs"]
mod feature_key_generate_test;
