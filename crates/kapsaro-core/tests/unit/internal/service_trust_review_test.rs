// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::online_verification::verify_trust_candidate_online;
use super::{
    enforce_read_trust_member_eligibility, execute_read_with_signer_trust,
    review_recipient_trust_with_confirmation, review_recipient_trust_with_confirmation_verifier,
    review_signer_trust_with_confirmation_verifier, review_write_recipient_trust,
    ReadSignerTrustReviewPlan, ReadTrustConfirmations, SignerTrustLabels, TrustReviewContext,
    WriteRecipientTrustReviewPlan,
};
use crate::service::trust::approval::ApprovedKnownKey;
use crate::service::trust::{RecipientTrustOutcome, SignerTrustOutcome, TrustApprovalCandidate};
use crate::service_test_utils::build_test_execution_context;
use crate::test_utils::setup_test_keystore_from_fixtures;

fn build_candidate(member_handle: &str, kid: &str) -> TrustApprovalCandidate {
    build_candidate_with_binding(member_handle, kid, false)
}

fn build_candidate_with_binding(
    member_handle: &str,
    kid: &str,
    github_binding_configured: bool,
) -> TrustApprovalCandidate {
    TrustApprovalCandidate::for_test(member_handle, kid, github_binding_configured)
}

fn build_verified_candidate(candidate: &TrustApprovalCandidate) -> TrustApprovalCandidate {
    let evidence = crate::service::online::VerifiedGitHubEvidence::for_test(
        candidate.service_candidate(),
        42,
        "octocat",
        "SHA256:test",
        100,
    );
    crate::service::trust::TrustApprovalCandidateBuilder::from_known_key_candidate(
        candidate.service_candidate(),
    )
    .with_verified_service_evidence(evidence)
    .with_online_verification_context(true, Some("verified".to_string()))
    .build()
}

fn build_failed_online_candidate(
    candidate: &TrustApprovalCandidate,
    message: &str,
) -> TrustApprovalCandidate {
    crate::service::trust::TrustApprovalCandidateBuilder::from_known_key_candidate(
        candidate.service_candidate(),
    )
    .with_online_verification_context(true, Some(message.to_string()))
    .build()
}

fn assert_manual_review_approval(approval: &ApprovedKnownKey, member_handle: &str, kid: &str) {
    assert_eq!(approval.member_handle().as_str(), member_handle);
    assert_eq!(approval.kid().as_str(), kid);
}

#[test]
fn test_execute_read_with_signer_trust_dedupes_signer_and_recipient_key_review() {
    let home = setup_test_keystore_from_fixtures("alice@example.com");
    let execution_context = build_test_execution_context(&home, "alice@example.com", None);
    let candidate = build_candidate("bob@example.com", "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0");
    let signer_outcome = SignerTrustOutcome::NeedsKnownKeyApproval(candidate.clone());
    let recipient_outcome = RecipientTrustOutcome::NeedsManualApproval(vec![candidate.clone()]);
    let mut reviewed_count = 0usize;

    execute_read_with_signer_trust(
        TrustReviewContext {
            trust: &execution_context,
            warnings: &[],
        },
        ReadSignerTrustReviewPlan {
            trust_outcome: &signer_outcome,
            recipient_trust_outcome: &recipient_outcome,
            labels: SignerTrustLabels {
                context: "decrypt keys",
                subject: "key",
            },
            allow_non_member: true,
        },
        |_warnings| {},
        ReadTrustConfirmations {
            known_key: |_candidate, _context_label| {
                panic!("signer-specific approval should not be used")
            },
            non_member_signer: |_candidate, _context_label, _recipients| Ok(false),
            recipients: |candidates, _context_label| {
                reviewed_count = candidates.len();
                Ok(candidates.to_vec())
            },
        },
        || Ok(()),
    )
    .unwrap();

    assert_eq!(reviewed_count, 1);
}

#[test]
fn test_review_write_recipient_trust_reuses_signer_key_approval_for_recipient() {
    let home = setup_test_keystore_from_fixtures("alice@example.com");
    let execution_context = build_test_execution_context(&home, "alice@example.com", None);
    let candidate = build_candidate("bob@example.com", "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0");
    let signer_outcome = SignerTrustOutcome::NeedsKnownKeyApproval(candidate.clone());
    let recipient_outcome = RecipientTrustOutcome::NeedsManualApproval(vec![candidate.clone()]);
    let mut signer_prompt_count = 0usize;
    let mut recipient_prompt_count = 0usize;

    review_write_recipient_trust(
        TrustReviewContext {
            trust: &execution_context,
            warnings: &[],
        },
        WriteRecipientTrustReviewPlan {
            signer_trust: Some((
                &signer_outcome,
                SignerTrustLabels {
                    context: "import input signer",
                    subject: "input signer",
                },
            )),
            recipient_trust: &recipient_outcome,
            recipient_context_label: "import recipients",
        },
        |_warnings| {},
        |_candidate, _context_label| {
            signer_prompt_count += 1;
            Ok(true)
        },
        |_candidate, _context_label, _recipients| Ok(false),
        |candidates, _context_label| {
            recipient_prompt_count += candidates.len();
            Ok(candidates.to_vec())
        },
    )
    .unwrap();

    assert_eq!(signer_prompt_count, 1);
    assert_eq!(recipient_prompt_count, 0);
}

#[test]
fn test_execute_read_with_signer_trust_reviews_recipients_after_non_member_acceptance() {
    let home = setup_test_keystore_from_fixtures("alice@example.com");
    let execution_context = build_test_execution_context(&home, "alice@example.com", None);
    let signer = build_candidate("mallory@example.com", "M0M0M0M0M0M0M0M0M0M0M0M0M0M0M0M0");
    let recipient = build_candidate("bob@example.com", "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0");
    let signer_outcome = SignerTrustOutcome::NeedsNonMemberAcceptance {
        candidate: signer,
        current_recipients: vec!["alice@example.com".to_string()],
    };
    let recipient_outcome = RecipientTrustOutcome::NeedsManualApproval(vec![recipient.clone()]);
    let mut accepted_non_member = false;
    let mut reviewed_recipient = None;
    let mut executed = false;

    execute_read_with_signer_trust(
        TrustReviewContext {
            trust: &execution_context,
            warnings: &[],
        },
        ReadSignerTrustReviewPlan {
            trust_outcome: &signer_outcome,
            recipient_trust_outcome: &recipient_outcome,
            labels: SignerTrustLabels {
                context: "decrypt keys",
                subject: "key",
            },
            allow_non_member: true,
        },
        |_warnings| {},
        ReadTrustConfirmations {
            known_key: |_candidate, _context_label| {
                panic!("known-key signer approval should not be used")
            },
            non_member_signer: |_candidate, _context_label, _recipients| {
                accepted_non_member = true;
                Ok(true)
            },
            recipients: |candidates, _context_label| {
                reviewed_recipient = Some((
                    candidates[0].member_handle().clone(),
                    candidates[0].kid().clone(),
                ));
                Ok(candidates.to_vec())
            },
        },
        || {
            executed = true;
            Ok(())
        },
    )
    .unwrap();

    assert!(accepted_non_member);
    assert_eq!(
        reviewed_recipient,
        Some((recipient.member_handle().clone(), recipient.kid().clone()))
    );
    assert!(executed);
}

#[test]
fn test_execute_read_with_signer_trust_stops_on_recipient_rejection_after_non_member_acceptance() {
    let home = setup_test_keystore_from_fixtures("alice@example.com");
    let execution_context = build_test_execution_context(&home, "alice@example.com", None);
    let signer = build_candidate("mallory@example.com", "M0M0M0M0M0M0M0M0M0M0M0M0M0M0M0M0");
    let recipient = build_candidate("bob@example.com", "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0");
    let signer_outcome = SignerTrustOutcome::NeedsNonMemberAcceptance {
        candidate: signer,
        current_recipients: vec!["alice@example.com".to_string()],
    };
    let recipient_outcome = RecipientTrustOutcome::NeedsManualApproval(vec![recipient]);
    let mut executed = false;

    let result = execute_read_with_signer_trust(
        TrustReviewContext {
            trust: &execution_context,
            warnings: &[],
        },
        ReadSignerTrustReviewPlan {
            trust_outcome: &signer_outcome,
            recipient_trust_outcome: &recipient_outcome,
            labels: SignerTrustLabels {
                context: "decrypt keys",
                subject: "key",
            },
            allow_non_member: true,
        },
        |_warnings| {},
        ReadTrustConfirmations {
            known_key: |_candidate, _context_label| {
                panic!("known-key signer approval should not be used")
            },
            non_member_signer: |_candidate, _context_label, _recipients| Ok(true),
            recipients: |_candidates, _context_label| Ok(Vec::new()),
        },
        || {
            executed = true;
            Ok(())
        },
    );

    let error = result.unwrap_err();
    assert!(error
        .format_user_message()
        .contains("one or more recipients"));
    assert!(!executed);
}

#[test]
fn test_review_signer_trust_with_confirmation_accepts_known_key_approval() {
    let candidate = build_candidate("bob@example.com", "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0");

    let approvals = review_signer_trust_with_confirmation_verifier(
        &SignerTrustOutcome::NeedsKnownKeyApproval(candidate.clone()),
        "decrypt signer",
        "signer",
        verify_trust_candidate_online,
        |_candidate, _context_label| Ok(true),
        |_candidate, _context_label, _recipients| Ok(false),
    )
    .unwrap();

    assert_eq!(approvals.len(), 1);
    assert_manual_review_approval(
        &approvals[0],
        candidate.member_handle().as_str(),
        candidate.kid().as_str(),
    );
}

#[test]
fn test_review_signer_trust_with_confirmation_populates_verified_github_for_tofu_prompt() {
    let candidate =
        build_candidate_with_binding("bob@example.com", "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0", true);
    let mut prompted_github = None;

    let approvals = review_signer_trust_with_confirmation_verifier(
        &SignerTrustOutcome::NeedsKnownKeyApproval(candidate.clone()),
        "decrypt signer",
        "signer",
        |_candidate| Ok(build_verified_candidate(&candidate)),
        |candidate, _context_label| {
            prompted_github = Some((
                candidate.github_id(),
                candidate.github_login().map(str::to_string),
            ));
            Ok(true)
        },
        |_candidate, _context_label, _recipients| Ok(false),
    )
    .unwrap();

    assert_eq!(approvals.len(), 1);
    assert_eq!(
        prompted_github,
        Some((Some(42), Some("octocat".to_string())))
    );
}

#[test]
fn test_review_signer_trust_with_confirmation_rejects_tofu_when_online_verification_fails() {
    let candidate =
        build_candidate_with_binding("bob@example.com", "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0", true);

    let result = review_signer_trust_with_confirmation_verifier(
        &SignerTrustOutcome::NeedsKnownKeyApproval(candidate.clone()),
        "decrypt signer",
        "signer",
        |_candidate| {
            Ok(build_failed_online_candidate(
                &candidate,
                "online verification failed",
            ))
        },
        |_candidate, _context_label| panic!("known-key prompt must not run"),
        |_candidate, _context_label, _recipients| Ok(false),
    );

    let error = result.unwrap_err();
    assert!(error
        .format_user_message()
        .contains("online verification failed"));
}

#[test]
fn test_review_signer_trust_with_confirmation_rejects_non_member_acceptance() {
    let candidate = build_candidate("bob@example.com", "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0");

    let result = review_signer_trust_with_confirmation_verifier(
        &SignerTrustOutcome::NeedsNonMemberAcceptance {
            candidate: candidate.clone(),
            current_recipients: vec!["alice@example.com".to_string()],
        },
        "decrypt signer",
        "signer",
        verify_trust_candidate_online,
        |_candidate, _context_label| Ok(false),
        |_candidate, _context_label, _recipients| Ok(false),
    );

    let error = result.unwrap_err();
    assert!(error
        .format_user_message()
        .contains("Non-member acceptance rejected"));
    assert!(error
        .format_user_message()
        .contains(candidate.member_handle().as_str()));
    assert!(error
        .format_user_message()
        .contains(candidate.kid().as_str()));
}

#[test]
fn test_review_signer_trust_with_confirmation_allows_non_member_after_failed_online_verification() {
    let candidate = build_candidate_with_binding(
        "mallory@example.com",
        "M0M0M0M0M0M0M0M0M0M0M0M0M0M0M0M0",
        true,
    );
    let mut warned_message = None;

    let approvals = review_signer_trust_with_confirmation_verifier(
        &SignerTrustOutcome::NeedsNonMemberAcceptance {
            candidate: candidate.clone(),
            current_recipients: vec!["alice@example.com".to_string()],
        },
        "decrypt signer",
        "signer",
        |_candidate| {
            Ok(build_failed_online_candidate(
                &candidate,
                "online verification failed",
            ))
        },
        |_candidate, _context_label| Ok(false),
        |candidate, _context_label, _recipients| {
            warned_message = candidate.online_verification_message().map(str::to_string);
            Ok(true)
        },
    )
    .unwrap();

    assert!(approvals.is_empty());
    assert_eq!(
        warned_message.as_deref(),
        Some("online verification failed")
    );
}

#[test]
fn test_review_recipient_trust_with_confirmation_rejects_partial_approval() {
    let alice = build_candidate("alice@example.com", "A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1");
    let bob = build_candidate("bob@example.com", "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0");

    let result = review_recipient_trust_with_confirmation(
        &RecipientTrustOutcome::NeedsManualApproval(vec![alice.clone(), bob.clone()]),
        "encrypt recipients",
        |_candidates: &[TrustApprovalCandidate], _context_label| Ok(vec![alice.clone()]),
    );

    let error = result.unwrap_err();
    assert!(error
        .format_user_message()
        .contains("one or more recipients"));
}

#[test]
fn test_review_recipient_trust_with_confirmation_populates_verified_github_for_tofu_prompt() {
    let alice = build_candidate_with_binding(
        "alice@example.com",
        "A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1",
        true,
    );
    let mut prompted_github = None;

    let approvals = review_recipient_trust_with_confirmation_verifier(
        &RecipientTrustOutcome::NeedsManualApproval(vec![alice.clone()]),
        "encrypt recipients",
        |candidate| Ok(build_verified_candidate(candidate)),
        |candidates: &[TrustApprovalCandidate], _context_label| {
            prompted_github = Some((
                candidates[0].github_id(),
                candidates[0].github_login().map(str::to_string),
            ));
            Ok(candidates.to_vec())
        },
    )
    .unwrap();

    assert_eq!(approvals.len(), 1);
    assert_eq!(
        prompted_github,
        Some((Some(42), Some("octocat".to_string())))
    );
}

#[test]
fn test_review_recipient_trust_with_confirmation_collects_all_approved_candidates() {
    let alice = build_candidate("alice@example.com", "A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1");
    let bob = build_candidate("bob@example.com", "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0");

    let approvals = review_recipient_trust_with_confirmation(
        &RecipientTrustOutcome::NeedsManualApproval(vec![alice.clone(), bob.clone()]),
        "encrypt recipients",
        |candidates: &[TrustApprovalCandidate], _context_label| Ok(candidates.to_vec()),
    )
    .unwrap();

    assert_eq!(approvals.len(), 2);
    assert_manual_review_approval(
        &approvals[0],
        alice.member_handle().as_str(),
        alice.kid().as_str(),
    );
    assert_manual_review_approval(
        &approvals[1],
        bob.member_handle().as_str(),
        bob.kid().as_str(),
    );
}

#[test]
fn test_enforce_read_trust_member_eligibility_rejects_run_policy() {
    let candidate = build_candidate("bob@example.com", "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0");

    let error = enforce_read_trust_member_eligibility(
        &SignerTrustOutcome::NeedsNonMemberAcceptance {
            candidate: candidate.clone(),
            current_recipients: vec!["alice@example.com".to_string()],
        },
        "run",
    )
    .unwrap_err();

    assert!(error
        .format_user_message()
        .contains("not eligible for run trust approval"));
    assert!(error
        .format_user_message()
        .contains(candidate.member_handle().as_str()));
    assert!(error
        .format_user_message()
        .contains(candidate.kid().as_str()));
}
