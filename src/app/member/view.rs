// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::errors::serialize_to_json_value;
use crate::io::ssh::protocol::build_sha256_fingerprint;
use crate::model::public_key::PublicKey;
use crate::Result;

use super::types::{
    MemberDocumentStatus, MemberDocumentView, MemberGithubClaim, MemberListEntry,
    MemberVerificationResult,
};

pub(crate) fn build_member_list_entry(public_key: PublicKey) -> Result<MemberListEntry> {
    Ok(MemberListEntry {
        member_id: public_key.protected.member_id.clone(),
        kid: public_key.protected.kid.clone(),
        document: serialize_to_json_value(&public_key)?,
    })
}

pub(crate) fn build_member_document_view(
    public_key: PublicKey,
    verification_warnings: Vec<String>,
) -> Result<MemberDocumentView> {
    let verification_status = if verification_warnings.is_empty() {
        MemberDocumentStatus::Valid
    } else {
        MemberDocumentStatus::Expired
    };

    let ssh_attestation_fingerprint =
        build_sha256_fingerprint(&public_key.protected.identity.attestation.pub_)?;

    Ok(MemberDocumentView {
        member_id: public_key.protected.member_id.clone(),
        kid: public_key.protected.kid.clone(),
        expires_at: public_key.protected.expires_at.clone(),
        created_at: public_key.protected.created_at.clone(),
        kem_curve: public_key.protected.identity.keys.kem.crv.clone(),
        sig_curve: public_key.protected.identity.keys.sig.crv.clone(),
        ssh_attestation_fingerprint,
        github_claim: public_key
            .protected
            .binding_claims
            .as_ref()
            .and_then(|claims| claims.github_account.as_ref())
            .map(|account| MemberGithubClaim {
                id: account.id,
                login: account.login.clone(),
            }),
        verification_status,
        verification_warnings,
        document: serialize_to_json_value(&public_key)?,
    })
}

pub(crate) fn build_member_verification_result(
    result: crate::io::verify_online::VerificationResult,
) -> MemberVerificationResult {
    let verified = result.is_verified();
    MemberVerificationResult {
        member_id: result.member_id,
        verified,
        message: result.message,
        fingerprint: result.fingerprint,
        matched_key_id: result.matched_key_id,
    }
}
