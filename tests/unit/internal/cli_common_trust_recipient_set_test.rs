// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::cli::common::trust::{
    format_member_key_review_lines, format_non_member_signer_review_lines,
    format_recipient_set_member_review_lines, format_recipient_set_review_lines,
    format_signer_key_review_lines, recipient_set_review_prompt, ArtifactRecipientReviewRow,
};
use crate::cli::stderr_color_guard::StderrColorGuard;
use console::strip_ansi_codes;
use kapsaro_core::api::trust::enforcement::ArtifactRecipientSetReview;
use kapsaro_core::api::trust::TrustApprovalCandidate;
use kapsaro_core::test_support::domain::common::WrapItem;
use kapsaro_core::test_support::domain::trust_store::{
    RecipientHandleHint, RecipientSetApprovalVia, RecipientSetRecord,
};
use kapsaro_core::test_support::operations::trust::recipient_sets::ArtifactRecipientSet;
use serial_test::serial;
use uuid::Uuid;

#[test]
fn test_format_signer_key_review_lines_uses_user_facing_copy_and_github_account() {
    let candidate = candidate_with_verified_github();

    let rendered = format_signer_key_review_lines(&candidate).join("\n");

    assert!(rendered.contains("Key review"));
    assert!(rendered.contains("This secret was signed by the member below."));
    assert!(rendered.contains("Approve only if this public key belongs to that member."));
    assert!(rendered.contains("Before approving, confirm the fingerprint with the member"));
    assert!(rendered.contains("member handle      bob@example.com"));
    assert!(rendered.contains("key id             KAD1-AAAA-1111-BBBB-2222-CCCC-3333-DDDD"));
    assert!(rendered.contains("SSH fingerprint    SHA256:test"));
    assert!(rendered.contains("GitHub account     octocat (id: 42, verified)"));
    assert!(!rendered.contains("GitHub check"));
    assert!(!rendered.contains("Context:"));
    assert!(!rendered.contains("decrypt signer"));
}

#[test]
fn test_format_non_member_signer_review_lines_says_decision_is_one_time_only() {
    let candidate = candidate_with_verified_github();

    let rendered =
        format_non_member_signer_review_lines(&candidate, &["alice@example.com".to_string()])
            .join("\n");

    assert!(rendered.contains("Signer outside active members"));
    assert!(rendered.contains("Accept only if you intentionally want to read this artifact once."));
    assert!(rendered.contains("This decision will not save the signer key as trusted."));
    assert!(rendered.contains("Current recipients"));
    assert!(rendered.contains("alice@example.com"));
    assert!(!rendered.contains("Context:"));
    assert!(!rendered.contains("decrypt signer"));
}

#[test]
fn test_format_non_member_signer_review_lines_warns_after_online_verification_failure() {
    let candidate = candidate_with_failed_github_verification();

    let rendered = format_non_member_signer_review_lines(&candidate, &[]).join("\n");

    assert!(rendered.contains(
        "Warning: GitHub online verification did not verify this signer: online verification failed"
    ));
    assert!(rendered.contains("GitHub account     not verified"));
}

#[test]
fn test_format_member_key_review_lines_uses_member_verify_copy() {
    let candidate = kapsaro_core::api::member::approval::MemberApprovalResult {
        member_handle: "bob@example.com".to_string(),
        kid: "KAD1AAAA1111BBBB2222CCCC3333DDDD".to_string(),
        verified: true,
        approved: false,
        review_required: true,
        already_known: false,
        message: "verified".to_string(),
        fingerprint: Some("SHA256:test".to_string()),
        github_id: Some(42),
        github_login: Some("octocat".to_string()),
        github_binding_configured: true,
        attestor_pub: Some("ssh-ed25519 AAAA test".to_string()),
        verified_github: None,
    };

    let rendered = format_member_key_review_lines(&candidate).join("\n");

    assert!(rendered.contains("Key review"));
    assert!(rendered.contains("You are approving the member key below."));
    assert!(rendered.contains("Approve only if this public key belongs to that member."));
    assert!(rendered.contains("member handle      bob@example.com"));
    assert!(rendered.contains("key id             KAD1-AAAA-1111-BBBB-2222-CCCC-3333-DDDD"));
    assert!(rendered.contains("GitHub account     octocat (id: 42, verified)"));
    assert!(!rendered.contains("artifact"));
    assert!(!rendered.contains("Context:"));
    assert!(!rendered.contains("member verify"));
}

#[test]
fn test_format_recipient_set_review_lines_uses_user_facing_copy_and_member_handles() {
    let current_kid = "KAD1AAAA1111BBBB2222CCCC3333DDDD".to_string();
    let current = ArtifactRecipientSet::from_wrap_items(
        Uuid::nil(),
        &[wrap_item("alice@example.com", &current_kid)],
    )
    .unwrap();
    let review = ArtifactRecipientSetReview::new(current, None);

    let rendered = format_recipient_set_review_lines(&review).join("\n");

    assert!(rendered.contains("Secret sharing review"));
    assert!(rendered.contains("This secret is shared with the members below."));
    assert!(rendered.contains("Approve only if this member set is expected for this secret."));
    assert!(rendered.contains("Approval is remembered on this device for future checks."));
    assert!(rendered.contains("Current members"));
    assert!(rendered.contains("member handle"));
    assert!(rendered.contains("key id"));
    assert!(rendered.contains("alice@example.com"));
    assert!(rendered.contains("KAD1-AAAA-1111-BBBB-2222-CCCC-3333-DDDD"));
    assert!(!rendered.contains(&current_kid));
    assert!(!rendered.contains("sid:"));
    assert!(!rendered.contains("recipient_sets"));
    assert!(!rendered.contains("Context:"));
    assert!(!rendered.contains("get signer"));
    assert_eq!(
        recipient_set_review_prompt(&review),
        "Trust this member set for this secret?"
    );
}

#[test]
fn test_format_recipient_set_review_lines_keeps_long_member_handle_and_dashed_kid_inline() {
    let member_handle = "avery.long.member.handle.for.release.engineering@example.com";
    let kid = "KAD1-AAAA-1111-BBBB-2222-CCCC-3333-DDDD";
    let current_kid = "KAD1AAAA1111BBBB2222CCCC3333DDDD".to_string();
    let current = ArtifactRecipientSet::from_wrap_items(
        Uuid::nil(),
        &[wrap_item(member_handle, &current_kid)],
    )
    .unwrap();
    let review = ArtifactRecipientSetReview::new(current, None);

    let lines = format_recipient_set_review_lines(&review);
    let rendered = lines.join("\n");

    assert!(rendered.contains(&format!("{member_handle}  {kid}")));
}

#[test]
#[serial]
fn test_format_recipient_set_review_lines_shows_colored_diff_for_changed_set() {
    let _guard = StderrColorGuard::new(true);
    let current_kid = "KAD1AAAA1111BBBB2222CCCC3333DDDD".to_string();
    let approved_kid = "KBD2AAAA1111BBBB2222CCCC3333DDDD".to_string();
    let current = ArtifactRecipientSet::from_wrap_items(
        Uuid::nil(),
        &[wrap_item("alice@example.com", &current_kid)],
    )
    .unwrap();
    let review =
        ArtifactRecipientSetReview::new(current, Some(recipient_set_record(&approved_kid, None)));

    let rendered = format_recipient_set_review_lines(&review).join("\n");
    let plain = strip_ansi_codes(&rendered);

    assert!(plain.contains("This secret's member set differs from your last review."));
    assert!(plain.contains("Approve only if this member change is expected."));
    assert!(plain.contains("Approval updates the remembered member set on this device."));
    assert!(plain.contains("Member changes"));
    assert!(plain.contains("+ alice@example.com  KAD1-AAAA-1111-BBBB-2222-CCCC-3333-DDDD"));
    assert!(plain.contains("- unknown            KBD2-AAAA-1111-BBBB-2222-CCCC-3333-DDDD"));
    assert!(rendered.contains("\u{1b}["));
    assert!(!rendered.contains(&approved_kid));
    assert_eq!(
        recipient_set_review_prompt(&review),
        "Update the trusted member set for this secret?"
    );
}

#[test]
#[serial]
fn test_format_recipient_set_review_lines_keeps_colored_diff_inline_after_stripping_ansi() {
    let _guard = StderrColorGuard::new(true);
    let member_handle = "avery.long.member.handle.for.release.engineering@example.com";
    let current_kid = "KAD1AAAA1111BBBB2222CCCC3333DDDD".to_string();
    let approved_kid = "KBD2AAAA1111BBBB2222CCCC3333DDDD".to_string();
    let current = ArtifactRecipientSet::from_wrap_items(
        Uuid::nil(),
        &[wrap_item(member_handle, &current_kid)],
    )
    .unwrap();
    let review =
        ArtifactRecipientSetReview::new(current, Some(recipient_set_record(&approved_kid, None)));

    let rendered = format_recipient_set_review_lines(&review).join("\n");
    let plain = strip_ansi_codes(&rendered);
    assert!(plain.contains(&format!(
        "{member_handle}  KAD1-AAAA-1111-BBBB-2222-CCCC-3333-DDDD"
    )));
}

#[test]
#[serial]
fn test_format_recipient_set_review_lines_keeps_diff_readable_without_color() {
    let _guard = StderrColorGuard::new(false);
    let current_kid = "KAD1AAAA1111BBBB2222CCCC3333DDDD".to_string();
    let approved_kid = "KBD2AAAA1111BBBB2222CCCC3333DDDD".to_string();
    let current = ArtifactRecipientSet::from_wrap_items(
        Uuid::nil(),
        &[wrap_item("alice@example.com", &current_kid)],
    )
    .unwrap();
    let review =
        ArtifactRecipientSetReview::new(current, Some(recipient_set_record(&approved_kid, None)));

    let rendered = format_recipient_set_review_lines(&review).join("\n");

    assert!(!rendered.contains("\u{1b}["));
    assert!(rendered.contains("+ alice@example.com  KAD1-AAAA-1111-BBBB-2222-CCCC-3333-DDDD"));
    assert!(rendered.contains("- unknown            KBD2-AAAA-1111-BBBB-2222-CCCC-3333-DDDD"));
}

#[test]
fn test_format_recipient_set_review_lines_keeps_long_handles_inline() {
    let current_kid = "KAD1AAAA1111BBBB2222CCCC3333DDDD".to_string();
    let long_handle = format!("{}@example.com", "a".repeat(116));
    let current = ArtifactRecipientSet::from_wrap_items(
        Uuid::nil(),
        &[wrap_item(&long_handle, &current_kid)],
    )
    .unwrap();
    let review = ArtifactRecipientSetReview::new(current, None);

    let rendered = format_recipient_set_review_lines(&review).join("\n");

    assert!(rendered.contains(&long_handle));
    assert!(rendered.contains("KAD1-AAAA-1111-BBBB-2222-CCCC-3333-DDDD"));
}

/// The read and rewrap paths reach the review with the set the last approval
/// stored, so a changed set is listed as the members it adds and removes.
#[test]
fn test_format_recipient_set_member_review_lines_lists_the_changed_members() {
    let current = [
        ArtifactRecipientReviewRow::new(
            "alice@example.com".to_string(),
            "KAD1AAAA1111BBBB2222CCCC3333DDDD".to_string(),
        ),
        ArtifactRecipientReviewRow::new(
            "carol@example.com".to_string(),
            "KCD3AAAA1111BBBB2222CCCC3333DDDD".to_string(),
        ),
    ];
    let approved = [
        ArtifactRecipientReviewRow::new(
            "alice@example.com".to_string(),
            "KAD1AAAA1111BBBB2222CCCC3333DDDD".to_string(),
        ),
        ArtifactRecipientReviewRow::new(
            "bob@example.com".to_string(),
            "KBD2AAAA1111BBBB2222CCCC3333DDDD".to_string(),
        ),
    ];

    let rendered = format_recipient_set_member_review_lines(&current, Some(&approved)).join("\n");
    let plain = strip_ansi_codes(&rendered);

    assert!(plain.contains("This secret's member set differs from your last review."));
    assert!(plain.contains("Approve only if this member change is expected."));
    assert!(plain.contains("Approval updates the remembered member set on this device."));
    assert!(plain.contains("Member changes"));
    assert!(plain.contains("  + carol@example.com"));
    assert!(plain.contains("  - bob@example.com"));
    assert!(plain.contains("    alice@example.com"));
}

#[test]
fn test_format_recipient_set_member_review_lines_introduces_a_first_review() {
    let rows = [ArtifactRecipientReviewRow::new(
        "alice@example.com".to_string(),
        "KAD1AAAA1111BBBB2222CCCC3333DDDD".to_string(),
    )];

    let rendered = format_recipient_set_member_review_lines(&rows, None).join("\n");

    assert!(rendered.contains("This secret is shared with the members below."));
    assert!(rendered.contains("Approve only if this member set is expected for this secret."));
    assert!(rendered.contains("Current members"));
}

fn recipient_set_record(kid: &str, hints: Option<Vec<RecipientHandleHint>>) -> RecipientSetRecord {
    RecipientSetRecord {
        sid: Uuid::nil().to_string(),
        recipient_kids: vec![kid.to_string()],
        recipient_set_hash: "hash".to_string(),
        approved_at: "2026-05-01T00:00:00Z".to_string(),
        approved_via: RecipientSetApprovalVia::ManualReview,
        recipient_handle_hints: hints,
    }
}

fn wrap_item(recipient_handle: &str, kid: &str) -> WrapItem {
    WrapItem {
        recipient_handle: recipient_handle.to_string(),
        kid: kid.to_string(),
        alg: "hpke-32-1-3".to_string(),
        enc: "enc".to_string(),
        ct: "ct".to_string(),
    }
}

fn candidate_with_verified_github() -> TrustApprovalCandidate {
    TrustApprovalCandidate::for_test_review(
        "bob@example.com",
        "KAD1AAAA1111BBBB2222CCCC3333DDDD",
        Some("SHA256:test".to_string()),
        true,
        Some((42, "octocat".to_string(), "SHA256:test".to_string(), 12345)),
        true,
        None,
        false,
    )
}

fn candidate_with_failed_github_verification() -> TrustApprovalCandidate {
    TrustApprovalCandidate::for_test_review(
        "bob@example.com",
        "KAD1AAAA1111BBBB2222CCCC3333DDDD",
        Some("SHA256:test".to_string()),
        true,
        None,
        true,
        Some("online verification failed".to_string()),
        true,
    )
}
