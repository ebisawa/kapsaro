// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public key document builders used during key generation.

use crate::crypto::sign::sign_detached_bytes;
use crate::feature::key::ssh_binding::SshBindingContext;
use crate::format::codec::base64_public::encode_base64url_nopad;
use crate::format::jcs;
use crate::format::kid::derive_public_key_kid;
use crate::format::public_key::{build_attestation_body_bytes, AttestationBodyInput};
use crate::format::signature::encode_ed25519_signature;
use crate::io::ssh::protocol::constants as ssh;
use crate::io::ssh::SshError;
use crate::model::public_key::{
    Attestation, BindingClaims, GithubAccount, IdentityKeys, PublicKey, PublicKeyParts,
};
use crate::support::kid::format_kid_display;
use crate::Result;
use ed25519_dalek::SigningKey;
use serde::Serialize;
use tracing::debug;

/// Parameters for building a public key.
pub struct PublicKeyDocumentParams<'a> {
    pub member_handle: &'a str,
    pub keys: IdentityKeys,
    pub binding_claims: Option<BindingClaims>,
    pub attestation: Attestation,
    pub created_at: &'a str,
    pub expires_at: &'a str,
    pub sig_sk: &'a SigningKey,
    pub debug: bool,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PublicKeyProtectedWithoutKid {
    format: String,
    subject_handle: String,
    keys: IdentityKeys,
    #[serde(skip_serializing_if = "Option::is_none")]
    binding_claims: Option<BindingClaims>,
    attestation: Attestation,
    expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
}

pub fn build_binding_claims(github_account: Option<GithubAccount>) -> Option<BindingClaims> {
    github_account.map(|github_account| BindingClaims {
        github_account: Some(github_account),
    })
}

/// Build public key with self-signature.
pub fn build_public_key(params: &PublicKeyDocumentParams<'_>) -> Result<PublicKey> {
    let protected_without_kid = PublicKeyProtectedWithoutKid {
        format: crate::model::wire::format::PUBLIC_KEY_V7.to_string(),
        subject_handle: params.member_handle.to_string(),
        keys: params.keys.clone(),
        binding_claims: params.binding_claims.clone(),
        attestation: params.attestation.clone(),
        expires_at: params.expires_at.to_string(),
        created_at: Some(params.created_at.to_string()),
    };
    let derived_kid = derive_public_key_kid(
        &serde_json::to_value(&protected_without_kid).map_err(crate::Error::from)?,
    )?;
    let protected = PublicKey::new(PublicKeyParts {
        subject_handle: params.member_handle.to_string(),
        kid: derived_kid.clone(),
        keys: params.keys.clone(),
        binding_claims: params.binding_claims.clone(),
        attestation: params.attestation.clone(),
        expires_at: params.expires_at.to_string(),
        created_at: Some(params.created_at.to_string()),
        signature: String::new(),
    })
    .protected;

    let protected_jcs = jcs::normalize(&protected)?;
    if params.debug {
        let kid_display = format_kid_display(&derived_kid).unwrap_or_else(|_| derived_kid.clone());
        debug!(
            "[CRYPTO] Ed25519: sign_detached_bytes (kid: {})",
            kid_display
        );
    }
    let signature = encode_ed25519_signature(&sign_detached_bytes(&protected_jcs, params.sig_sk)?);

    Ok(PublicKey {
        protected,
        signature,
    })
}

/// Build attestation for identity keys.
pub fn build_attestation(
    ssh_binding: &SshBindingContext,
    input: &AttestationBodyInput<'_>,
) -> Result<Attestation> {
    let body = build_attestation_body_bytes(input)?;

    let raw_sig = ssh_binding
        .backend
        .sign_sshsig(ssh::ATTESTATION_NAMESPACE, &ssh_binding.public_key, &body)
        .map_err(|e| {
            crate::Error::from(SshError::build_operation_failed_error_with_source(
                format!("Failed to sign attestation: {}", e),
                e,
            ))
        })?;

    let sig_b64url = encode_base64url_nopad(raw_sig.as_bytes());

    Ok(Attestation {
        method: ssh::ATTESTATION_METHOD_SSH_SIGN.to_string(),
        pub_: ssh_binding.public_key.clone(),
        sig: sig_b64url,
    })
}
