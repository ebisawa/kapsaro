// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Candidate-bound GitHub evidence tests.
//! Ensures only successful verification can authorize its exact reviewed key.

use crate::io::verify_online::{VerificationResult, VerifiedGithubIdentity};
use crate::model::public_key::{BindingClaims, GithubAccount};
use crate::service::trust::{KnownKeyApprovalEvidence, KnownKeyReviewCandidate, TrustApproval};

use super::VerifiedGitHubEvidence;

const ALICE: &str = "alice@example.com";
const BOB: &str = "bob@example.com";
const ALICE_KID: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const BOB_KID: &str = "1123456789ABCDEFGHJKMNPQRSTVWXYZ";
const ALICE_ATTESTOR: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test";

fn candidate(kid: &str) -> KnownKeyReviewCandidate {
    candidate_with(ALICE, kid, ALICE_ATTESTOR)
}

fn candidate_with(handle: &str, kid: &str, attestor: &str) -> KnownKeyReviewCandidate {
    candidate_with_account_id(handle, kid, attestor, 42)
}

fn candidate_with_account_id(
    handle: &str,
    kid: &str,
    attestor: &str,
    account_id: u64,
) -> KnownKeyReviewCandidate {
    let mut document = crate::test_utils::load_fixture_public_key(ALICE);
    document.protected.subject_handle = handle.to_string();
    document.protected.kid = kid.to_string();
    if attestor != ALICE_ATTESTOR {
        document.protected.attestation.pub_ = attestor.to_string();
    }
    document.protected.binding_claims = Some(BindingClaims {
        github_account: Some(GithubAccount {
            id: account_id,
            login: "alice".to_string(),
        }),
    });
    KnownKeyReviewCandidate::from_public_key(&document).expect("typed candidate")
}

fn verified_result(candidate: &KnownKeyReviewCandidate) -> VerificationResult {
    VerificationResult::verified(
        ALICE,
        "verified".to_string(),
        VerifiedGithubIdentity::new(
            42,
            "alice".to_string(),
            candidate.fingerprint().unwrap().to_string(),
            7,
        ),
    )
}

#[test]
fn test_verified_github_evidence_authorizes_only_its_candidate() {
    let alice = candidate(ALICE_KID);
    let other = candidate(BOB_KID);
    let evidence = VerifiedGitHubEvidence::from_result(&alice, verified_result(&alice))
        .expect("successful verification produces evidence");

    assert!(TrustApproval::known_key(
        &alice,
        KnownKeyApprovalEvidence::none().with_verified_github_account(evidence.clone()),
    )
    .is_ok());
    let error = TrustApproval::known_key(
        &other,
        KnownKeyApprovalEvidence::none().with_verified_github_account(evidence),
    )
    .expect_err("evidence from another kid must not authorize this candidate");
    assert_eq!(error.rule(), Some("E_TRUST_APPROVAL_EVIDENCE_MISMATCH"));
}

#[test]
fn test_github_bound_candidate_rejects_approval_without_verified_evidence() {
    let alice = candidate(ALICE_KID);

    let error = TrustApproval::known_key(&alice, KnownKeyApprovalEvidence::none())
        .expect_err("a GitHub claim requires successfully verified evidence");

    assert_eq!(error.rule(), Some("E_TRUST_APPROVAL_EVIDENCE_MISMATCH"));
}

#[test]
fn test_github_verification_rejects_a_result_for_another_member() {
    let bob = candidate_with(BOB, ALICE_KID, ALICE_ATTESTOR);

    let error = VerifiedGitHubEvidence::from_result(&bob, verified_result(&candidate(ALICE_KID)))
        .expect_err("a verification result for another member must be rejected");

    assert_eq!(
        error.rule(),
        Some("E_ONLINE_VERIFICATION_IDENTITY_MISMATCH")
    );
}

#[test]
fn test_verified_github_evidence_rejects_a_different_attestor() {
    let alice = candidate(ALICE_KID);
    let changed_attestor = candidate_with(
        ALICE,
        ALICE_KID,
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5BBBB changed",
    );
    let evidence = VerifiedGitHubEvidence::from_result(&alice, verified_result(&alice))
        .expect("successful verification produces evidence");

    let error = TrustApproval::known_key(
        &changed_attestor,
        KnownKeyApprovalEvidence::none().with_verified_github_account(evidence),
    )
    .expect_err("evidence for another attestor must be rejected");

    assert_eq!(error.rule(), Some("E_TRUST_APPROVAL_EVIDENCE_MISMATCH"));
}

#[test]
fn test_verified_github_evidence_rejects_a_different_account_id() {
    let alice = candidate(ALICE_KID);
    let changed_account = candidate_with_account_id(ALICE, ALICE_KID, ALICE_ATTESTOR, 43);
    let evidence = VerifiedGitHubEvidence::from_result(&alice, verified_result(&alice))
        .expect("successful verification produces evidence");

    let error = TrustApproval::known_key(
        &changed_account,
        KnownKeyApprovalEvidence::none().with_verified_github_account(evidence),
    )
    .expect_err("evidence for another GitHub account must be rejected");

    assert_eq!(error.rule(), Some("E_TRUST_APPROVAL_EVIDENCE_MISMATCH"));
}

#[test]
fn test_ssh_attestor_evidence_must_match_the_candidate() {
    let alice = candidate(ALICE_KID);
    let evidence = KnownKeyApprovalEvidence::none()
        .with_ssh_attestor_public_key("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5BBBB changed");

    let error = TrustApproval::known_key(&alice, evidence)
        .expect_err("different SSH attestor evidence must be rejected");

    assert_eq!(error.rule(), Some("E_TRUST_APPROVAL_EVIDENCE_MISMATCH"));
}

#[test]
fn test_verified_github_evidence_rejects_account_id_mismatch() {
    let alice = candidate(ALICE_KID);
    let result = VerificationResult::verified(
        ALICE,
        "verified".to_string(),
        VerifiedGithubIdentity::new(
            43,
            "renamed-alice".to_string(),
            "SHA256:test".to_string(),
            7,
        ),
    );

    let error = VerifiedGitHubEvidence::from_result(&alice, result).unwrap_err();

    assert_eq!(
        error.rule(),
        Some("E_ONLINE_VERIFICATION_IDENTITY_MISMATCH")
    );
}

#[test]
fn test_verified_github_evidence_rejects_candidate_fingerprint_mismatch() {
    let alice = candidate(ALICE_KID);
    let mut result = verified_result(&alice);
    let expected = alice.fingerprint().unwrap();
    result.fingerprint = Some(format!("{expected}-changed"));
    result.verified_github.as_mut().unwrap().fingerprint = format!("{expected}-changed");

    let error = VerifiedGitHubEvidence::from_result(&alice, result).unwrap_err();

    assert_eq!(
        error.rule(),
        Some("E_ONLINE_VERIFICATION_EVIDENCE_MISMATCH")
    );
}

#[test]
fn test_verified_github_evidence_rejects_result_fingerprint_mismatch() {
    let alice = candidate(ALICE_KID);
    let mut result = verified_result(&alice);
    result.fingerprint = Some("SHA256:outer-mismatch".to_string());

    let error = VerifiedGitHubEvidence::from_result(&alice, result).unwrap_err();

    assert_eq!(
        error.rule(),
        Some("E_ONLINE_VERIFICATION_EVIDENCE_MISMATCH")
    );
}

#[test]
fn test_verified_github_evidence_rejects_result_matched_key_id_mismatch() {
    let alice = candidate(ALICE_KID);
    let mut result = verified_result(&alice);
    result.matched_key_id = Some(8);

    let error = VerifiedGitHubEvidence::from_result(&alice, result).unwrap_err();

    assert_eq!(
        error.rule(),
        Some("E_ONLINE_VERIFICATION_EVIDENCE_MISMATCH")
    );
}

#[test]
fn test_verified_github_evidence_keeps_current_login() {
    let alice = candidate(ALICE_KID);
    let expected_fingerprint = alice.fingerprint().unwrap().to_string();
    let result = VerificationResult::verified(
        ALICE,
        "verified".to_string(),
        VerifiedGithubIdentity::new(42, "renamed-alice".to_string(), expected_fingerprint, 7),
    );

    let evidence = VerifiedGitHubEvidence::from_result(&alice, result).unwrap();

    assert_eq!(evidence.account().login(), "renamed-alice");
}
