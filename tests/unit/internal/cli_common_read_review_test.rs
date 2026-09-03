// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for CLI trust review error mapping and verification ordering.
//! Exercises private presentation helpers without network access.

use std::cell::Cell;

use super::*;
use kapsaro_core::test_support::operations::trust::review::build_known_key_review_candidate;
use kapsaro_core::ErrorKind;

const TEST_KID: &str = "KAD1AAAA1111BBBB2222CCCC3333DDDD";

fn candidate(github_binding_configured: bool) -> KnownKeyReviewCandidate {
    build_known_key_review_candidate(
        "reviewer@example.com",
        TEST_KID,
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnly",
        github_binding_configured,
    )
}

#[test]
fn test_non_interactive_signer_review_reports_unknown_signer_rule_error() {
    let error = build_non_interactive_key_error(&candidate(false), true);

    assert_eq!(error.rule(), Some("E_TRUST_UNKNOWN_SIGNER"));
}

#[test]
fn test_non_interactive_recipient_review_reports_unknown_recipient_rule_error() {
    let error = build_non_interactive_key_error(&candidate(false), false);

    assert_eq!(error.rule(), Some("E_TRUST_RECIPIENT_UNKNOWN"));
}

#[test]
fn test_non_interactive_initial_recipient_set_review_reports_missing_trust_rule_error() {
    let error = build_non_interactive_recipient_set_error(TrustReviewKind::RecipientSet);

    assert_eq!(error.rule(), Some("E_RECIPIENT_TRUST_MISSING"));
}

#[test]
fn test_non_interactive_changed_recipient_set_review_reports_changed_set_rule_error() {
    let error = build_non_interactive_recipient_set_error(TrustReviewKind::ChangedRecipientSet);

    assert_eq!(error.rule(), Some("E_RECIPIENT_SET_CHANGED"));
}

#[test]
fn test_known_key_verifier_failure_preserves_error_before_confirmation_error() {
    let confirmation_count = Cell::new(0);
    let result = review_known_key_with_confirmation(
        &candidate(true),
        "signer key",
        KnownKeyReviewSubject::Signer,
        |_| {
            Err(Error::build_config_error_with_rule(
                "E_TEST_VERIFIER_FAILED",
                "test verifier failure",
            ))
        },
        || {
            confirmation_count.set(confirmation_count.get() + 1);
            Ok(true)
        },
    );

    let error = result.expect_err("verifier failure must stop known-key review");
    assert_eq!(error.kind(), ErrorKind::Config);
    assert_eq!(error.rule(), Some("E_TEST_VERIFIER_FAILED"));
    assert_eq!(error.format_user_message(), "test verifier failure");
    assert_eq!(confirmation_count.get(), 0);
}

#[test]
fn test_known_key_review_guidance_requires_an_out_of_band_fingerprint_check() {
    let lines = format_key_approval_review_lines("Test key review");

    assert!(lines.join("\n").contains(
        "confirm the fingerprint with the member through a trusted\n\
         channel, such as an in-person check, a signed message, or a fingerprint shared\n\
         outside this repository"
    ));
}

#[test]
fn test_known_key_rejection_names_the_reviewed_subject() {
    for (subject, expected_message) in [
        (
            KnownKeyReviewSubject::Signer,
            "Signer key approval was rejected",
        ),
        (
            KnownKeyReviewSubject::Recipient,
            "Recipient key approval was rejected",
        ),
    ] {
        let result = review_known_key_with_confirmation(
            &candidate(false),
            subject.review_context("signer key"),
            subject,
            |_| panic!("candidate without a GitHub binding must not use the verifier"),
            || Ok(false),
        );

        let error = result.expect_err("explicit rejection must stop known-key approval");
        assert_eq!(error.rule(), Some("E_TRUST_REJECTED"));
        assert_eq!(error.format_user_message(), expected_message);
    }
}

#[test]
fn test_non_member_verifier_failure_allows_one_shot_confirmation() {
    let confirmation_count = Cell::new(0);
    let result = review_non_member_with_confirmation(
        &candidate(true),
        &[],
        |_| {
            Err(Error::build_config_error_with_rule(
                "E_TEST_VERIFIER_FAILED",
                "test verifier failure",
            ))
        },
        || {
            confirmation_count.set(confirmation_count.get() + 1);
            Ok(true)
        },
    );

    let review = result.expect("online verification is advisory for one-shot non-member review");
    assert_eq!(review.failure.as_deref(), Some("test verifier failure"));
    assert_eq!(confirmation_count.get(), 1);
}
