// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use crate::app::rewrap::types::{
    IncomingPromotionCandidate, IncomingVerificationCategory, IncomingVerificationItem,
    IncomingVerificationReport,
};
use crate::feature::trust::judgment::{SelfTrustSet, TrustIdentity};
use crate::io::verify_online::VerifiedGithubIdentity;
use crate::model::public_key::{Attestation, Identity, IdentityKeys, JwkOkpPublicKey, PublicKey};
use crate::model::trust_store::{KnownKey, KnownKeyApprovalVia};
use crate::support::codec::base64_public::encode_base64url_nopad;

use super::{build_promotion_review_plan, build_promotion_review_session_with_verifier};

fn kid_for(member_id: &str) -> &'static str {
    match member_id {
        "alice" => "KAD1AAAA1111BBBB2222CCCC3333DDDD",
        "bob" => "KBD1AAAA1111BBBB2222CCCC3333DDDD",
        "carol" => "KCD1AAAA1111BBBB2222CCCC3333DDDD",
        _ => "KDD1AAAA1111BBBB2222CCCC3333DDDD",
    }
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

fn binding_configured_result(member_id: &str) -> IncomingPromotionCandidate {
    build_candidate(
        member_id,
        IncomingVerificationCategory::BindingConfigured,
        "pending online verification",
        true,
        None,
    )
}

fn build_candidate(
    member_id: &str,
    category: IncomingVerificationCategory,
    message: &str,
    github_binding_configured: bool,
    verified_github: Option<VerifiedGithubIdentity>,
) -> IncomingPromotionCandidate {
    let review = IncomingVerificationItem {
        member_id: member_id.to_string(),
        kid: kid_for(member_id).to_string(),
        category,
        message: message.to_string(),
        fingerprint: Some("SHA256:abc".to_string()),
        verified_github,
        github_binding_configured,
        attestor_pub: Some("ssh-ed25519 AAAA test".to_string()),
    };

    IncomingPromotionCandidate {
        review,
        source_path: std::path::PathBuf::from(format!("members/incoming/{}.json", member_id)),
        source_content: "{}".to_string(),
        public_key: PublicKey::new(
            member_id.to_string(),
            kid_for(member_id).to_string(),
            Identity {
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
                attestation: Attestation {
                    method: "ssh".to_string(),
                    pub_: "ssh-ed25519 AAAA test".to_string(),
                    sig: "sig".to_string(),
                },
            },
            None,
            "2030-01-01T00:00:00Z".to_string(),
            None,
            "signature".to_string(),
        ),
    }
}

fn known_key(member_id: &str) -> KnownKey {
    KnownKey {
        kid: kid_for(member_id).to_string(),
        member_id: member_id.to_string(),
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
    assert_eq!(result.failed_candidates[0].review.member_id, "bob");
    assert!(result.auto_accepted_candidates.is_empty());
    assert!(result.prompt_candidates.is_empty());
}

#[test]
fn test_build_promotion_review_plan_not_configured_non_interactive_errors() {
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
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("TOFU confirmation required"));
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
    assert_eq!(result.auto_accepted_candidates[0].review.member_id, "alice");
    assert!(result.prompt_candidates.is_empty());
}

#[test]
fn test_build_promotion_review_plan_detects_known_key_integrity_anomaly_before_prompt() {
    let report = build_report(vec![binding_configured_result("alice")], vec![], vec![]);
    let conflicting_known_key = KnownKey {
        kid: kid_for("alice").to_string(),
        member_id: "bob".to_string(),
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
        .contains("candidate has member_id 'alice'"));
}

#[test]
fn test_build_promotion_review_session_builds_prompt_view_without_online_verify_for_not_configured()
{
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
    let review_plan =
        build_promotion_review_plan(&report, &[], &SelfTrustSet::default(), true).unwrap();

    let session = build_promotion_review_session_with_verifier(&review_plan, |_candidate| {
        panic!("online verifier should not run for candidates without GitHub binding");
    })
    .unwrap();

    assert!(session.view().failed_candidates.is_empty());
    assert_eq!(session.view().prompt_candidates.len(), 1);
    assert_eq!(
        session.view().prompt_candidates[0].candidate.member_id,
        "carol"
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
fn test_build_promotion_review_session_restores_accepted_candidates_from_prompt_selection() {
    let report = build_report(
        vec![binding_configured_result("alice")],
        vec![],
        vec![build_candidate(
            "carol",
            IncomingVerificationCategory::NotConfigured,
            "no github",
            false,
            None,
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
    let accepted = session.into_accepted_candidates(&["alice".to_string(), "carol".to_string()]);
    let accepted_ids = accepted
        .into_iter()
        .map(|candidate| candidate.review.member_id)
        .collect::<Vec<_>>();

    assert_eq!(accepted_ids, vec!["alice".to_string(), "carol".to_string()]);
}

#[test]
fn test_build_promotion_review_session_empty_report_produces_empty_view() {
    let review_plan = crate::app::rewrap::types::IncomingPromotionReviewPlan::default();

    let session =
        build_promotion_review_session_with_verifier(&review_plan, |_candidate| unreachable!())
            .unwrap();

    assert!(session.view().failed_candidates.is_empty());
    assert!(session.view().prompt_candidates.is_empty());
    assert!(session.into_accepted_candidates(&[]).is_empty());
}

#[test]
fn test_build_promotion_review_plan_auto_accepts_self_candidate_without_known_key() {
    let report = build_report(vec![binding_configured_result("alice")], vec![], vec![]);

    let result = build_promotion_review_plan(&report, &[], &self_trust(), false).unwrap();

    assert_eq!(result.auto_accepted_candidates.len(), 1);
    assert_eq!(result.auto_accepted_candidates[0].review.member_id, "alice");
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
fn test_build_promotion_review_plan_rejects_self_candidate_when_local_identity_is_missing() {
    let report = build_report(vec![binding_configured_result("alice")], vec![], vec![]);

    let result =
        build_promotion_review_plan(&report, &[], &SelfTrustSet::new("alice", [[7u8; 32]]), true);

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
        kid: kid_for("alice").to_string(),
        member_id: "bob".to_string(),
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
        .contains("candidate has member_id 'alice'"));
}
