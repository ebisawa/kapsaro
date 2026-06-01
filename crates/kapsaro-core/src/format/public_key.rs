// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! PublicKey canonical input builders.
//!
//! This module owns JCS input construction for PublicKey statement bindings.

use crate::format::jcs;
use crate::model::public_key::{BindingClaims, IdentityKeys};
use crate::model::wire::context::SSHSIG_MESSAGE_PUBLIC_KEY_ATTESTATION_V1;
use crate::Result;
use serde::Serialize;

/// Borrowed input for PublicKey attestation body construction.
pub struct AttestationBodyInput<'a> {
    pub subject_handle: &'a str,
    pub keys: &'a IdentityKeys,
    pub binding_claims: Option<&'a BindingClaims>,
    pub created_at: Option<&'a str>,
    pub expires_at: &'a str,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct AttestationBody<'a> {
    p: &'static str,
    subject_handle: &'a str,
    keys: &'a IdentityKeys,
    #[serde(skip_serializing_if = "Option::is_none")]
    binding_claims: Option<&'a BindingClaims>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<&'a str>,
    expires_at: &'a str,
}

/// Build JCS bytes for the PublicKey SSH attestation body.
pub fn build_attestation_body_bytes(input: &AttestationBodyInput<'_>) -> Result<Vec<u8>> {
    jcs::normalize(&AttestationBody {
        p: SSHSIG_MESSAGE_PUBLIC_KEY_ATTESTATION_V1,
        subject_handle: input.subject_handle,
        keys: input.keys,
        binding_claims: input.binding_claims,
        created_at: input.created_at,
        expires_at: input.expires_at,
    })
}
