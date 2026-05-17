// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::io::verify_online::{VerificationResult, VerificationStatus, VerifiedGithubIdentity};
use crate::model::public_key::{
    Attestation, BindingClaims, GithubAccount, Identity, IdentityKeys, JwkOkpPublicKey, PublicKey,
};
use crate::support::codec::base64_public::encode_base64url_nopad;

use super::TrustApprovalCandidateBuilder;

const MEMBER_HANDLE: &str = "bob@example.com";
const KID: &str = "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0";
const ATTESTOR_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN8W0SKx53Hf0YlBT/Zr/x77q11T0xDY8WBGV7Suk52Q test@example.com";

fn build_public_key(github_binding_configured: bool) -> PublicKey {
    let binding_claims = github_binding_configured.then(|| BindingClaims {
        github_account: Some(GithubAccount {
            id: 42,
            login: "claimed-login".to_string(),
        }),
    });

    PublicKey::new(
        MEMBER_HANDLE.to_string(),
        KID.to_string(),
        Identity {
            keys: IdentityKeys {
                kem: JwkOkpPublicKey {
                    kty: "OKP".to_string(),
                    crv: "X25519".to_string(),
                    x: encode_base64url_nopad(&[2u8; 32]),
                },
                sig: JwkOkpPublicKey {
                    kty: "OKP".to_string(),
                    crv: "Ed25519".to_string(),
                    x: encode_base64url_nopad(&[1u8; 32]),
                },
            },
            attestation: Attestation {
                method: "ssh".to_string(),
                pub_: ATTESTOR_PUB.to_string(),
                sig: "sig".to_string(),
            },
        },
        binding_claims,
        "2030-01-01T00:00:00Z".to_string(),
        None,
        "signature".to_string(),
    )
}

#[test]
fn test_trust_approval_candidate_from_public_key_sets_shared_review_fields() {
    let public_key = build_public_key(true);

    let candidate = TrustApprovalCandidateBuilder::from_public_key(&public_key).build();

    assert_eq!(candidate.member_handle.as_str(), MEMBER_HANDLE);
    assert_eq!(candidate.kid.as_str(), KID);
    assert!(candidate
        .fingerprint
        .as_deref()
        .unwrap()
        .starts_with("SHA256:"));
    assert_eq!(candidate.github_id, None);
    assert_eq!(candidate.github_login, None);
    assert_eq!(candidate.attestor_pub.as_deref(), Some(ATTESTOR_PUB));
    assert_eq!(candidate.verified_github, None);
    assert!(candidate.github_binding_configured);
    assert!(!candidate.online_verification_attempted);
    assert_eq!(candidate.online_verification_message, None);
    assert_eq!(candidate.public_key, Some(public_key));
    assert!(candidate.requires_out_of_band_verification);
}

#[test]
fn test_trust_approval_candidate_from_verification_uses_verified_github_as_evidence() {
    let public_key = build_public_key(true);
    let verified_github = VerifiedGithubIdentity::new(
        100,
        "current-login".to_string(),
        "SHA256:verified".to_string(),
        9,
    );
    let verification = VerificationResult {
        member_handle: MEMBER_HANDLE.to_string(),
        status: VerificationStatus::Verified,
        message: "verified".to_string(),
        fingerprint: Some(verified_github.fingerprint.clone()),
        matched_key_id: Some(verified_github.matched_key_id),
        github_claim_present: true,
        verified_github: Some(verified_github.clone()),
    };

    let candidate = TrustApprovalCandidateBuilder::from_public_key(&public_key)
        .with_verification_result(&verification)
        .build();

    assert_eq!(candidate.fingerprint.as_deref(), Some("SHA256:verified"));
    assert_eq!(candidate.github_id, Some(100));
    assert_eq!(candidate.github_login.as_deref(), Some("current-login"));
    assert_eq!(candidate.verified_github, Some(verified_github));
    assert!(candidate.online_verification_attempted);
    assert_eq!(
        candidate.online_verification_message.as_deref(),
        Some("verified")
    );
}

#[test]
fn test_trust_approval_candidate_keeps_fingerprint_when_verification_has_none() {
    let public_key = build_public_key(true);
    let verification = VerificationResult {
        member_handle: MEMBER_HANDLE.to_string(),
        status: VerificationStatus::Failed,
        message: "not found".to_string(),
        fingerprint: None,
        matched_key_id: None,
        github_claim_present: true,
        verified_github: None,
    };
    let original = TrustApprovalCandidateBuilder::from_public_key(&public_key).build();

    let candidate = TrustApprovalCandidateBuilder::from_public_key(&public_key)
        .with_verification_result(&verification)
        .build();

    assert_eq!(candidate.fingerprint, original.fingerprint);
    assert_eq!(candidate.github_id, None);
    assert_eq!(candidate.github_login, None);
    assert_eq!(candidate.verified_github, None);
    assert!(candidate.online_verification_attempted);
    assert_eq!(
        candidate.online_verification_message.as_deref(),
        Some("not found")
    );
}
