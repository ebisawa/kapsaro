// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public key document builders used during key generation.

use crate::crypto::sign::sign_detached_bytes;
use crate::feature::key::ssh_binding::SshBindingContext;
use crate::format::jcs;
use crate::format::kid::derive_public_key_kid;
use crate::io::ssh::protocol::constants as ssh;
use crate::io::ssh::SshError;
use crate::model::identifiers::alg;
use crate::model::public_key::{
    Attestation, BindingClaims, GithubAccount, Identity, IdentityKeys, PublicKey,
};
use crate::support::codec::base64_public::encode_base64url_nopad;
use crate::support::kid::format_kid_display;
use crate::Result;
use ed25519_dalek::SigningKey;
use serde::Serialize;
use tracing::debug;

/// Parameters for building a public key.
pub struct PublicKeyDocumentParams<'a> {
    pub member_id: &'a str,
    pub identity: Identity,
    pub created_at: &'a str,
    pub expires_at: &'a str,
    pub sig_sk: &'a SigningKey,
    pub debug: bool,
    pub github_account: Option<GithubAccount>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PublicKeyProtectedWithoutKid {
    format: String,
    member_id: String,
    identity: Identity,
    #[serde(skip_serializing_if = "Option::is_none")]
    binding_claims: Option<BindingClaims>,
    expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
}

/// Build public key with self-signature.
pub fn build_public_key(params: &PublicKeyDocumentParams<'_>) -> Result<PublicKey> {
    let binding_claims = params
        .github_account
        .clone()
        .map(|github_account| BindingClaims {
            github_account: Some(github_account),
        });
    let protected_without_kid = PublicKeyProtectedWithoutKid {
        format: crate::model::identifiers::format::PUBLIC_KEY_V4.to_string(),
        member_id: params.member_id.to_string(),
        identity: params.identity.clone(),
        binding_claims: binding_claims.clone(),
        expires_at: params.expires_at.to_string(),
        created_at: Some(params.created_at.to_string()),
    };
    let derived_kid = derive_public_key_kid(
        &serde_json::to_value(&protected_without_kid).map_err(crate::Error::from)?,
    )?;
    let protected = PublicKey::new(
        params.member_id.to_string(),
        derived_kid.clone(),
        params.identity.clone(),
        binding_claims,
        params.expires_at.to_string(),
        Some(params.created_at.to_string()),
        String::new(),
    )
    .protected;

    let protected_jcs = jcs::normalize(&protected)?;
    if params.debug {
        let kid_display = format_kid_display(&derived_kid).unwrap_or_else(|_| derived_kid.clone());
        debug!(
            "[CRYPTO] Ed25519: sign_detached_bytes (kid: {})",
            kid_display
        );
    }
    let signature = sign_detached_bytes(&protected_jcs, params.sig_sk, alg::SIGNATURE_ED25519)?;

    Ok(PublicKey {
        protected,
        signature,
    })
}

/// Build attestation for identity keys.
pub fn build_attestation(
    ssh_binding: &SshBindingContext,
    identity_keys: &IdentityKeys,
) -> Result<Attestation> {
    let identity_keys_jcs = jcs::normalize(identity_keys)?;

    let raw_sig = ssh_binding
        .backend
        .sign_sshsig(
            ssh::ATTESTATION_NAMESPACE,
            &ssh_binding.public_key,
            &identity_keys_jcs,
        )
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
