// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use crate::feature::trust::judgment::{SelfTrustSet, TrustIdentity};
use crate::format::codec::base64_public::encode_base64url_nopad;
use crate::io::verify_online::VerifiedGithubIdentity;
use crate::io::workspace::members::PromotionDestinationState;
use crate::model::public_key::{
    Attestation, IdentityKeys, JwkOkpPublicKey, PublicKey, PublicKeyParts,
};
use crate::model::trust_store::{KnownKey, KnownKeyApprovalVia};
use crate::service::rewrap::types::{
    IncomingPromotionCandidate, IncomingVerificationCategory, IncomingVerificationItem,
    IncomingVerificationReport,
};

use super::{build_promotion_review_plan, build_promotion_review_session_with_verifier};

fn placeholder_kid_for(member_handle: &str) -> &'static str {
    match member_handle {
        "alice" => "KAD1AAAA1111BBBB2222CCCC3333DDDD",
        "bob" => "KBD1AAAA1111BBBB2222CCCC3333DDDD",
        "carol" => "KCD1AAAA1111BBBB2222CCCC3333DDDD",
        _ => "KDD1AAAA1111BBBB2222CCCC3333DDDD",
    }
}

fn public_key_for(member_handle: &str) -> PublicKey {
    let mut public_key = PublicKey::new(PublicKeyParts {
        subject_handle: member_handle.to_string(),
        kid: placeholder_kid_for(member_handle).to_string(),
        keys: IdentityKeys {
            kem: JwkOkpPublicKey {
                kty: "OKP".to_string(),
                crv: "X25519".to_string(),
                x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            },
            sig: JwkOkpPublicKey {
                kty: "OKP".to_string(),
                crv: "Ed25519".to_string(),
                x: encode_base64url_nopad(&[1u8; 32]),
            },
        },
        binding_claims: None,
        attestation: Attestation {
            method: "ssh".to_string(),
            pub_: "ssh-ed25519 AAAA test".to_string(),
            sig: "sig".to_string(),
        },
        expires_at: "2030-01-01T00:00:00Z".to_string(),
        created_at: None,
        signature: "signature".to_string(),
    });
    crate::test_utils::refresh_public_key_kid(&mut public_key).unwrap();
    public_key
}

fn kid_for(member_handle: &str) -> String {
    public_key_for(member_handle).protected.kid
}

fn build_report(
    binding_configured: Vec<IncomingPromotionCandidate>,
    failed: Vec<IncomingPromotionCandidate>,
    not_configured: Vec<IncomingPromotionCandidate>,
) -> IncomingVerificationReport {
    IncomingVerificationReport {
        binding_configured,
        failed,
        not_configured,
    }
}

fn binding_configured_result(member_handle: &str) -> IncomingPromotionCandidate {
    build_candidate(
        member_handle,
        IncomingVerificationCategory::BindingConfigured,
        "pending online verification",
        true,
        None,
    )
}

fn binding_configured_result_with_github(member_handle: &str) -> IncomingPromotionCandidate {
    build_candidate(
        member_handle,
        IncomingVerificationCategory::BindingConfigured,
        "pending online verification",
        true,
        Some(VerifiedGithubIdentity::new(
            999999,
            "offline-test-user".to_string(),
            "SHA256:abc".to_string(),
            1,
        )),
    )
}

fn build_candidate(
    member_handle: &str,
    category: IncomingVerificationCategory,
    message: &str,
    github_binding_configured: bool,
    verified_github: Option<VerifiedGithubIdentity>,
) -> IncomingPromotionCandidate {
    let public_key = public_key_for(member_handle);
    let review = IncomingVerificationItem {
        member_handle: member_handle.to_string(),
        kid: public_key.protected.kid.clone(),
        category,
        message: message.to_string(),
        fingerprint: Some("SHA256:abc".to_string()),
        verified_github,
        verified_service_evidence: None,
        github_binding_configured,
        attestor_pub: Some("ssh-ed25519 AAAA test".to_string()),
    };

    IncomingPromotionCandidate {
        review,
        source_content: "{}".to_string(),
        destination: PromotionDestinationState::Missing,
        public_key,
    }
}

fn build_fixture_candidate(
    member_handle: &str,
    category: IncomingVerificationCategory,
    message: &str,
    github_binding_configured: bool,
) -> IncomingPromotionCandidate {
    let public_key = crate::test_utils::load_fixture_public_key(member_handle);
    let mut candidate = build_candidate(
        member_handle,
        category,
        message,
        github_binding_configured,
        None,
    );
    candidate.review.kid = public_key.protected.kid.clone();
    candidate.review.attestor_pub = Some(public_key.protected.attestation.pub_.clone());
    candidate.public_key = public_key;
    candidate
}

fn known_key(member_handle: &str) -> KnownKey {
    KnownKey {
        kid: kid_for(member_handle),
        subject_handle: member_handle.to_string(),
        approved_at: "2026-04-01T00:00:00Z".to_string(),
        approved_via: KnownKeyApprovalVia::ManualReview,
        evidence: None,
        extra: BTreeMap::new(),
    }
}

fn self_trust() -> SelfTrustSet {
    let identity =
        TrustIdentity::from_public_key(&binding_configured_result("alice").public_key).unwrap();
    SelfTrustSet::new("alice", [*identity.sig_x()])
}

#[test]
fn test_build_promotion_review_plan_keeps_failed_candidates_without_aborting_batch() {
    let report = build_report(
        vec![],
        vec![build_candidate(
            "bob",
            IncomingVerificationCategory::Failed,
            "err",
            false,
            None,
        )],
        vec![],
    );

    let result = build_promotion_review_plan(&report, &[], &SelfTrustSet::default(), true).unwrap();

    assert_eq!(result.failed_candidates.len(), 1);
    assert_eq!(result.failed_candidates[0].review.member_handle, "bob");
    assert!(result.auto_accepted_candidates.is_empty());
    assert!(result.prompt_candidates.is_empty());
}

#[test]
fn test_build_promotion_review_plan_not_configured_without_review_errors() {
    let report = build_report(
        vec![],
        vec![],
        vec![build_candidate(
            "carol",
            IncomingVerificationCategory::NotConfigured,
            "no github",
            false,
            None,
        )],
    );

    let result = build_promotion_review_plan(&report, &[], &SelfTrustSet::default(), false);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("E_TRUST_REJECTED"));
}

#[test]
fn test_build_promotion_review_plan_failed_only_non_interactive_still_succeeds() {
    let report = build_report(
        vec![],
        vec![build_candidate(
            "carol",
            IncomingVerificationCategory::Failed,
            "online verification failed",
            true,
            None,
        )],
        vec![],
    );

    let result =
        build_promotion_review_plan(&report, &[], &SelfTrustSet::default(), false).unwrap();

    assert_eq!(result.failed_candidates.len(), 1);
    assert!(result.auto_accepted_candidates.is_empty());
    assert!(result.prompt_candidates.is_empty());
}

#[test]
fn test_build_promotion_review_plan_auto_accepts_known_kid() {
    let report = build_report(vec![binding_configured_result("alice")], vec![], vec![]);

    let result = build_promotion_review_plan(
        &report,
        &[known_key("alice")],
        &SelfTrustSet::default(),
        false,
    )
    .unwrap();

    assert_eq!(result.auto_accepted_candidates.len(), 1);
    assert_eq!(
        result.auto_accepted_candidates[0].review.member_handle,
        "alice"
    );
    assert!(result.prompt_candidates.is_empty());
}

#[test]
fn test_build_promotion_review_session_skips_online_verify_for_known_github_binding() {
    let report = build_report(
        vec![binding_configured_result_with_github("bob")],
        vec![],
        vec![],
    );
    let review_plan = build_promotion_review_plan(
        &report,
        &[known_key("bob")],
        &SelfTrustSet::default(),
        false,
    )
    .unwrap();

    let session = build_promotion_review_session_with_verifier(&review_plan, |_candidate| {
        panic!("online verifier should not run for auto-accepted known incoming keys");
    })
    .unwrap();
    let (accepted, approvals) = session.into_accepted_candidates_and_approvals(&[]).unwrap();

    assert_eq!(accepted.len(), 1);
    assert!(approvals.is_empty());
    assert_eq!(accepted[0].review.member_handle, "bob");
    assert!(accepted[0].review.github_binding_configured);
}

#[test]
fn test_build_promotion_review_plan_detects_known_key_integrity_anomaly_before_prompt() {
    let report = build_report(vec![binding_configured_result("alice")], vec![], vec![]);
    let conflicting_known_key = KnownKey {
        kid: kid_for("alice"),
        subject_handle: "bob".to_string(),
        approved_at: "2026-04-01T00:00:00Z".to_string(),
        approved_via: KnownKeyApprovalVia::ManualReview,
        evidence: None,
        extra: BTreeMap::new(),
    };

    let result = build_promotion_review_plan(
        &report,
        &[conflicting_known_key],
        &SelfTrustSet::default(),
        true,
    );

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Candidate subject: alice"));
}

#[test]
fn test_build_promotion_review_session_builds_prompt_view_without_online_verify_for_not_configured()
{
    let report = build_report(
        vec![],
        vec![],
        vec![build_fixture_candidate(
            "bob@example.com",
            IncomingVerificationCategory::NotConfigured,
            "no github",
            false,
        )],
    );
    let review_plan =
        build_promotion_review_plan(&report, &[], &SelfTrustSet::default(), true).unwrap();

    let session = build_promotion_review_session_with_verifier(&review_plan, |_candidate| {
        panic!("online verifier should not run for candidates without GitHub binding");
    })
    .unwrap();

    assert!(session.view().failed_candidates.is_empty());
    assert_eq!(session.view().prompt_candidates.len(), 1);
    assert_eq!(
        session.view().prompt_candidates[0]
            .candidate
            .member_handle()
            .as_str(),
        "bob@example.com"
    );
}

#[test]
fn test_build_promotion_review_session_moves_failed_online_verification_to_failed_candidates() {
    let report = build_report(vec![binding_configured_result("alice")], vec![], vec![]);
    let review_plan =
        build_promotion_review_plan(&report, &[], &SelfTrustSet::default(), true).unwrap();

    let session = build_promotion_review_session_with_verifier(&review_plan, |candidate| {
        let mut reviewed = candidate.clone();
        reviewed.review.category = IncomingVerificationCategory::Failed;
        reviewed.review.message = "online verification failed".to_string();
        Ok(reviewed)
    })
    .unwrap();

    assert_eq!(session.view().failed_candidates.len(), 1);
    assert!(session.view().prompt_candidates.is_empty());
}

#[test]
fn test_build_promotion_review_session_keeps_later_prompt_after_verifier_error() {
    let report = build_report(
        vec![
            build_fixture_candidate(
                "alice@example.com",
                IncomingVerificationCategory::BindingConfigured,
                "pending online verification",
                true,
            ),
            build_fixture_candidate(
                "bob@example.com",
                IncomingVerificationCategory::BindingConfigured,
                "pending online verification",
                true,
            ),
        ],
        vec![],
        vec![],
    );
    let review_plan =
        build_promotion_review_plan(&report, &[], &SelfTrustSet::default(), true).unwrap();

    let session = build_promotion_review_session_with_verifier(&review_plan, |candidate| {
        if candidate.review.member_handle == "alice@example.com" {
            return Err(crate::Error::build_verification_error(
                "V-GITHUB-API".to_string(),
                "GitHub API unavailable".to_string(),
            ));
        }
        let mut reviewed = candidate.clone();
        reviewed.review.category = IncomingVerificationCategory::Verified;
        reviewed.review.verified_github = Some(VerifiedGithubIdentity::new(
            42,
            "bob-current".to_string(),
            "SHA256:abc".to_string(),
            7,
        ));
        Ok(reviewed)
    })
    .unwrap();

    assert_eq!(session.view().failed_candidates.len(), 1);
    assert_eq!(
        session.view().failed_candidates[0].member_handle,
        "alice@example.com"
    );
    assert!(session.view().failed_candidates[0]
        .message
        .contains("GitHub API unavailable"));
    assert_eq!(session.view().prompt_candidates.len(), 1);
    assert_eq!(
        session.view().prompt_candidates[0]
            .candidate
            .member_handle()
            .as_str(),
        "bob@example.com"
    );
    let (accepted, approvals) = session
        .into_accepted_candidates_and_approvals(&[
            "alice@example.com".to_string(),
            "bob@example.com".to_string(),
        ])
        .unwrap();
    assert!(accepted
        .iter()
        .all(|candidate| candidate.review.member_handle == "bob@example.com"));
    assert_eq!(approvals.len(), 1);
}

#[test]
fn test_build_promotion_review_session_restores_accepted_candidates_from_prompt_selection() {
    let report = build_report(
        vec![build_fixture_candidate(
            "alice@example.com",
            IncomingVerificationCategory::BindingConfigured,
            "pending online verification",
            true,
        )],
        vec![],
        vec![build_fixture_candidate(
            "bob@example.com",
            IncomingVerificationCategory::NotConfigured,
            "no github",
            false,
        )],
    );
    let review_plan =
        build_promotion_review_plan(&report, &[], &SelfTrustSet::default(), true).unwrap();

    let session = build_promotion_review_session_with_verifier(&review_plan, |candidate| {
        let mut reviewed = candidate.clone();
        reviewed.review.category = IncomingVerificationCategory::Verified;
        reviewed.review.message = "verified".to_string();
        reviewed.review.verified_github = Some(VerifiedGithubIdentity::new(
            12345,
            "alice-gh".to_string(),
            "SHA256:abc".to_string(),
            1,
        ));
        Ok(reviewed)
    })
    .unwrap();

    assert_eq!(session.view().prompt_candidates.len(), 2);
    let (accepted, approvals) = session
        .into_accepted_candidates_and_approvals(&[
            "alice@example.com".to_string(),
            "bob@example.com".to_string(),
        ])
        .unwrap();
    let accepted_ids = accepted
        .into_iter()
        .map(|candidate| candidate.review.member_handle)
        .collect::<Vec<_>>();

    assert_eq!(
        accepted_ids,
        vec![
            "alice@example.com".to_string(),
            "bob@example.com".to_string()
        ]
    );
    assert_eq!(approvals.len(), 2);
}

#[test]
fn test_build_promotion_review_session_empty_report_produces_empty_view() {
    let review_plan = crate::service::rewrap::types::IncomingPromotionReviewPlan::default();

    let session =
        build_promotion_review_session_with_verifier(&review_plan, |_candidate| unreachable!())
            .unwrap();

    assert!(session.view().failed_candidates.is_empty());
    assert!(session.view().prompt_candidates.is_empty());
    let (accepted, approvals) = session.into_accepted_candidates_and_approvals(&[]).unwrap();
    assert!(accepted.is_empty());
    assert!(approvals.is_empty());
}

#[test]
fn test_build_promotion_review_plan_auto_accepts_self_candidate_without_known_key() {
    let report = build_report(vec![binding_configured_result("alice")], vec![], vec![]);

    let result = build_promotion_review_plan(&report, &[], &self_trust(), false).unwrap();

    assert_eq!(result.auto_accepted_candidates.len(), 1);
    assert_eq!(
        result.auto_accepted_candidates[0].review.member_handle,
        "alice"
    );
    assert!(result.prompt_candidates.is_empty());
}

#[test]
fn test_build_promotion_review_plan_rejects_self_candidate_when_identity_mismatches() {
    let report = build_report(vec![binding_configured_result("alice")], vec![], vec![]);
    let mismatched_self_trust = SelfTrustSet::new("alice", [[7u8; 32]]);

    let result = build_promotion_review_plan(&report, &[], &mismatched_self_trust, true);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("E_REWRAP_SELF_PROMOTION_MISMATCH"));
}

#[test]
fn test_build_promotion_review_plan_preserves_integrity_anomaly_for_self_candidate() {
    let report = build_report(vec![binding_configured_result("alice")], vec![], vec![]);
    let conflicting_known_key = KnownKey {
        kid: kid_for("alice"),
        subject_handle: "bob".to_string(),
        approved_at: "2026-04-01T00:00:00Z".to_string(),
        approved_via: KnownKeyApprovalVia::ManualReview,
        evidence: None,
        extra: BTreeMap::new(),
    };

    let result =
        build_promotion_review_plan(&report, &[conflicting_known_key], &self_trust(), true);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Candidate subject: alice"));
}
