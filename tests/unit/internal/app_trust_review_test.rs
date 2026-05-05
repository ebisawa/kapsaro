// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::{
    enforce_read_trust_member_eligibility, execute_read_with_signer_trust,
    execute_write_with_recipient_trust, review_recipient_trust_with_confirmation,
    review_recipient_trust_with_confirmation_verifier,
    review_rewrap_signer_requirements_with_confirmation,
    review_rewrap_signer_requirements_with_confirmation_verifier,
    review_signer_trust_with_confirmation, review_signer_trust_with_confirmation_verifier,
    ReadSignerTrustReviewPlan, SignerTrustLabels, TrustExecutionContext,
    WriteRecipientTrustReviewPlan,
};
use crate::app::rewrap::types::RewrapSignerRequirement;
use crate::app::trust::approval::ApprovedKnownKey;
use crate::app::trust::{RecipientTrustOutcome, SignerTrustOutcome, TrustApprovalCandidate};
use crate::app_test_utils::{build_test_command_options, build_test_execution_context};
use crate::feature::trust::known_keys::KnownKeyIdentity;
use crate::io::verify_online::VerifiedGithubIdentity;
use crate::model::public_key::{
    Attestation, BindingClaims, GithubAccount, Identity, IdentityKeys, JwkOkpPublicKey, PublicKey,
};
use crate::test_utils::{
    kid as test_kid, member_handle as test_member_handle, setup_test_keystore_from_fixtures,
};
use std::path::{Path, PathBuf};

fn build_candidate(member_handle: &str, kid: &str) -> TrustApprovalCandidate {
    build_candidate_with_binding(member_handle, kid, false)
}

fn build_candidate_with_binding(
    member_handle: &str,
    kid: &str,
    github_binding_configured: bool,
) -> TrustApprovalCandidate {
    TrustApprovalCandidate {
        member_handle: test_member_handle(member_handle),
        kid: test_kid(kid),
        fingerprint: Some("SHA256:test".to_string()),
        github_id: None,
        github_login: None,
        attestor_pub: Some("ssh-ed25519 AAAA test".to_string()),
        verified_github: None,
        github_binding_configured,
        online_verification_attempted: false,
        online_verification_message: None,
        public_key: Some(build_public_key(
            member_handle,
            kid,
            github_binding_configured,
        )),
        requires_out_of_band_verification: true,
    }
}

fn build_public_key(member_handle: &str, kid: &str, github_binding_configured: bool) -> PublicKey {
    let binding_claims = github_binding_configured.then(|| BindingClaims {
        github_account: Some(GithubAccount {
            id: 42,
            login: "octocat".to_string(),
        }),
    });

    PublicKey::new(
        member_handle.to_string(),
        kid.to_string(),
        Identity {
            keys: IdentityKeys {
                kem: JwkOkpPublicKey {
                    kty: "OKP".to_string(),
                    crv: "X25519".to_string(),
                    x: "kem-x".to_string(),
                },
                sig: JwkOkpPublicKey {
                    kty: "OKP".to_string(),
                    crv: "Ed25519".to_string(),
                    x: "sig-x".to_string(),
                },
            },
            attestation: Attestation {
                method: "ssh".to_string(),
                pub_: "ssh-ed25519 AAAA test".to_string(),
                sig: "sig".to_string(),
            },
        },
        binding_claims,
        "2030-01-01T00:00:00Z".to_string(),
        None,
        "signature".to_string(),
    )
}

fn build_verified_candidate(candidate: &TrustApprovalCandidate) -> TrustApprovalCandidate {
    let verified_github =
        VerifiedGithubIdentity::new(42, "octocat".to_string(), "SHA256:test".to_string(), 100);
    let mut reviewed = candidate.clone();
    reviewed.github_id = Some(verified_github.id);
    reviewed.github_login = Some(verified_github.login.clone());
    reviewed.verified_github = Some(verified_github);
    reviewed.online_verification_attempted = true;
    reviewed.online_verification_message = Some("verified".to_string());
    reviewed
}

fn build_failed_online_candidate(
    candidate: &TrustApprovalCandidate,
    message: &str,
) -> TrustApprovalCandidate {
    let mut reviewed = candidate.clone();
    reviewed.online_verification_attempted = true;
    reviewed.online_verification_message = Some(message.to_string());
    reviewed
}

fn assert_manual_review_approval(approval: &ApprovedKnownKey, member_handle: &str, kid: &str) {
    let identity = KnownKeyIdentity::from(approval);
    assert_eq!(identity.member_handle(), member_handle);
    assert_eq!(identity.kid(), kid);
}

#[test]
fn test_execute_read_with_signer_trust_saves_approval_before_execute() {
    let home = setup_test_keystore_from_fixtures("alice@example.com");
    let options = build_test_command_options(home.path(), None);
    let execution_context = build_test_execution_context(&home, "alice@example.com", None);
    let candidate = build_candidate("alice@example.com", &execution_context.key_ctx.kid);
    let outcome = SignerTrustOutcome::NeedsKnownKeyApproval(candidate);
    let mut executed = false;

    let result = execute_read_with_signer_trust(
        TrustExecutionContext {
            options: &options,
            execution: &execution_context,
            warnings: &[],
        },
        ReadSignerTrustReviewPlan {
            trust_outcome: &outcome,
            labels: SignerTrustLabels {
                context: "decrypt signer",
                subject: "signer",
            },
            allow_non_member: true,
        },
        |_warnings| {},
        |_candidate, _context_label| Ok(true),
        |_candidate, _context_label, _recipients| Ok(false),
        || {
            executed = true;
            Ok(())
        },
    );

    let error = result.unwrap_err();
    assert!(error
        .format_user_message()
        .contains("must not be stored in known_keys"));
    assert!(!executed);
}

#[test]
fn test_execute_write_with_recipient_trust_saves_approval_before_execute() {
    let home = setup_test_keystore_from_fixtures("alice@example.com");
    let options = build_test_command_options(home.path(), None);
    let execution_context = build_test_execution_context(&home, "alice@example.com", None);
    let candidate = build_candidate("alice@example.com", &execution_context.key_ctx.kid);
    let outcome = RecipientTrustOutcome::NeedsManualApproval(vec![candidate]);
    let mut executed = false;

    let result = execute_write_with_recipient_trust(
        TrustExecutionContext {
            options: &options,
            execution: &execution_context,
            warnings: &[],
        },
        WriteRecipientTrustReviewPlan {
            signer_trust: None,
            recipient_trust: &outcome,
            recipient_context_label: "encrypt recipients",
        },
        |_warnings| {},
        |_candidate, _context_label| Ok(false),
        |_candidate, _context_label, _recipients| Ok(false),
        |candidates, _context_label| Ok(candidates.to_vec()),
        || {
            executed = true;
            Ok(())
        },
    );

    let error = result.unwrap_err();
    assert!(error
        .format_user_message()
        .contains("must not be stored in known_keys"));
    assert!(!executed);
}

#[test]
fn test_review_signer_trust_with_confirmation_accepts_known_key_approval() {
    let candidate = build_candidate("bob@example.com", "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0");

    let approvals = review_signer_trust_with_confirmation(
        &SignerTrustOutcome::NeedsKnownKeyApproval(candidate.clone()),
        "decrypt signer",
        "signer",
        |_candidate, _context_label| Ok(true),
        |_candidate, _context_label, _recipients| Ok(false),
    )
    .unwrap();

    assert_eq!(approvals.len(), 1);
    assert_manual_review_approval(&approvals[0], &candidate.member_handle, &candidate.kid);
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
            prompted_github = Some((candidate.github_id, candidate.github_login.clone()));
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

    let result = review_signer_trust_with_confirmation(
        &SignerTrustOutcome::NeedsNonMemberAcceptance {
            candidate: candidate.clone(),
            current_recipients: vec!["alice@example.com".to_string()],
        },
        "decrypt signer",
        "signer",
        |_candidate, _context_label| Ok(false),
        |_candidate, _context_label, _recipients| Ok(false),
    );

    let error = result.unwrap_err();
    assert!(error
        .format_user_message()
        .contains("Non-member acceptance rejected"));
    assert!(error
        .format_user_message()
        .contains(candidate.member_handle.as_str()));
    assert!(error.format_user_message().contains(candidate.kid.as_str()));
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
            warned_message = candidate.online_verification_message.clone();
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
            prompted_github = Some((candidates[0].github_id, candidates[0].github_login.clone()));
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
    assert_manual_review_approval(&approvals[0], &alice.member_handle, &alice.kid);
    assert_manual_review_approval(&approvals[1], &bob.member_handle, &bob.kid);
}

#[test]
fn test_review_rewrap_signer_requirements_with_confirmation_prompts_non_member_per_artifact() {
    let candidate = build_candidate("mallory@example.com", "M0M0M0M0M0M0M0M0M0M0M0M0M0M0M0M0");
    let requirements = vec![
        RewrapSignerRequirement {
            file_path: PathBuf::from("secrets/one.json"),
            outcome: SignerTrustOutcome::NeedsNonMemberAcceptance {
                candidate: candidate.clone(),
                current_recipients: vec!["alice@example.com".to_string()],
            },
        },
        RewrapSignerRequirement {
            file_path: PathBuf::from("secrets/two.json"),
            outcome: SignerTrustOutcome::NeedsNonMemberAcceptance {
                candidate,
                current_recipients: vec!["alice@example.com".to_string()],
            },
        },
    ];
    let mut prompted_paths = Vec::new();

    let approvals = review_rewrap_signer_requirements_with_confirmation(
        &requirements,
        "rewrap signer",
        "signer trust",
        |_candidate, _context_label, _path: &Path| Ok(true),
        |_candidate, _context_label, _recipients, path: &Path| {
            prompted_paths.push(path.to_path_buf());
            Ok(true)
        },
    )
    .unwrap();

    assert!(approvals.is_empty());
    assert_eq!(
        prompted_paths,
        vec![
            PathBuf::from("secrets/one.json"),
            PathBuf::from("secrets/two.json"),
        ]
    );
}

#[test]
fn test_review_rewrap_signer_requirements_with_confirmation_allows_non_member_after_failed_online_verification(
) {
    let candidate = build_candidate_with_binding(
        "mallory@example.com",
        "M0M0M0M0M0M0M0M0M0M0M0M0M0M0M0M0",
        true,
    );
    let requirements = vec![RewrapSignerRequirement {
        file_path: PathBuf::from("secrets/one.json"),
        outcome: SignerTrustOutcome::NeedsNonMemberAcceptance {
            candidate: candidate.clone(),
            current_recipients: vec!["alice@example.com".to_string()],
        },
    }];
    let mut warned = None;

    let approvals = review_rewrap_signer_requirements_with_confirmation_verifier(
        &requirements,
        "rewrap signer",
        "signer trust",
        |_candidate| {
            Ok(build_failed_online_candidate(
                &candidate,
                "online verification failed",
            ))
        },
        |_candidate, _context_label, _path: &Path| Ok(true),
        |candidate, _context_label, _recipients, _path: &Path| {
            warned = candidate.online_verification_message.clone();
            Ok(true)
        },
    )
    .unwrap();

    assert!(approvals.is_empty());
    assert_eq!(warned.as_deref(), Some("online verification failed"));
}

#[test]
fn test_review_rewrap_signer_requirements_with_confirmation_dedupes_known_key_approvals() {
    let candidate = build_candidate("bob@example.com", "B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0");
    let requirements = vec![
        RewrapSignerRequirement {
            file_path: PathBuf::from("secrets/one.json"),
            outcome: SignerTrustOutcome::NeedsKnownKeyApproval(candidate.clone()),
        },
        RewrapSignerRequirement {
            file_path: PathBuf::from("secrets/two.json"),
            outcome: SignerTrustOutcome::NeedsKnownKeyApproval(candidate.clone()),
        },
    ];
    let mut prompted_paths = Vec::new();

    let approvals = review_rewrap_signer_requirements_with_confirmation(
        &requirements,
        "rewrap signer",
        "signer trust",
        |_candidate, _context_label, path: &Path| {
            prompted_paths.push(path.to_path_buf());
            Ok(true)
        },
        |_candidate, _context_label, _recipients, _path: &Path| Ok(false),
    )
    .unwrap();

    assert_eq!(approvals.len(), 1);
    assert_manual_review_approval(&approvals[0], &candidate.member_handle, &candidate.kid);
    assert_eq!(prompted_paths, vec![PathBuf::from("secrets/one.json")]);
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
        .contains(candidate.member_handle.as_str()));
    assert!(error.format_user_message().contains(candidate.kid.as_str()));
}
