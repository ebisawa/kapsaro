// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::cli::common::output::trust::review::{
    format_candidate_review_lines, format_failed_promotion_review_lines,
};
use kapsaro_core::cli_api::app::rewrap::promotion::PromotionReviewFailure;
use kapsaro_core::cli_api::app::trust::TrustApprovalCandidate;

fn candidate(
    member_handle: impl Into<String>,
    fingerprint: Option<String>,
    github_binding_configured: bool,
    verified: bool,
    attempted: bool,
    message: Option<String>,
) -> TrustApprovalCandidate {
    let member_handle = member_handle.into();
    TrustApprovalCandidate::for_test_review(
        &member_handle,
        "KAD1AAAA1111BBBB2222CCCC3333DDDD",
        fingerprint,
        github_binding_configured,
        verified.then(|| (42, "octocat".to_string(), "SHA256:test".to_string(), 12345)),
        attempted,
        message,
        !verified,
    )
}

#[test]
fn test_format_candidate_review_lines_includes_required_fields() {
    let candidate = candidate(
        "bob@example.com",
        Some("SHA256:test".to_string()),
        true,
        false,
        false,
        None,
    );

    let lines = format_candidate_review_lines(&candidate);
    let rendered = lines.join("\n");

    assert!(rendered.contains("member handle      bob@example.com"));
    assert!(rendered.contains("key id             KAD1-AAAA-1111-BBBB-2222-CCCC-3333-DDDD"));
    assert!(rendered.contains("SSH fingerprint    SHA256:test"));
    assert!(rendered.contains("GitHub account     not verified"));
}

#[test]
fn test_format_candidate_review_lines_warns_when_github_binding_is_missing() {
    let candidate = candidate(
        "bob@example.com",
        Some("SHA256:test".to_string()),
        false,
        false,
        false,
        None,
    );

    let lines = format_candidate_review_lines(&candidate);
    let rendered = lines.join("\n");

    assert!(rendered.contains("key id             KAD1-AAAA-1111-BBBB-2222-CCCC-3333-DDDD"));
    assert!(rendered.contains("GitHub account     not configured"));
}

#[test]
fn test_format_candidate_review_lines_shows_github_id_without_login() {
    let candidate = candidate("bob@example.com", None, true, false, false, None);

    let lines = format_candidate_review_lines(&candidate);
    let rendered = lines.join("\n");

    assert!(rendered.contains("GitHub account     not verified"));
    assert!(!rendered.contains("verified)"));
}

#[test]
fn test_format_candidate_review_lines_warns_when_github_claim_is_unverified() {
    let candidate = candidate(
        "bob@example.com",
        Some("SHA256:test".to_string()),
        true,
        false,
        false,
        None,
    );

    let lines = format_candidate_review_lines(&candidate);
    let rendered = lines.join("\n");

    assert!(rendered.contains("GitHub account     not verified"));
    assert!(rendered.contains("online verification was not completed"));
}

#[test]
fn test_format_candidate_review_lines_shows_online_verification_failure_message() {
    let candidate = candidate(
        "bob@example.com",
        Some("SHA256:test".to_string()),
        true,
        false,
        true,
        Some("online verification failed".to_string()),
    );

    let lines = format_candidate_review_lines(&candidate);
    let rendered = lines.join("\n");

    assert!(rendered.contains("GitHub account     not verified"));
}

#[test]
fn test_format_candidate_review_lines_shows_verified_github_mark() {
    let candidate = candidate(
        "bob@example.com",
        Some("SHA256:test".to_string()),
        true,
        true,
        true,
        None,
    );

    let lines = format_candidate_review_lines(&candidate);
    let rendered = lines.join("\n");

    assert!(rendered.contains("GitHub account     octocat (id: 42, verified)"));
    assert!(
        !rendered.contains("not yet trusted"),
        "Should not show warning text when verified. Rendered: {}",
        rendered
    );
}

#[test]
fn test_format_candidate_review_lines_no_verified_mark_without_online_verification() {
    let candidate = candidate(
        "bob@example.com",
        Some("SHA256:test".to_string()),
        true,
        false,
        false,
        None,
    );

    let lines = format_candidate_review_lines(&candidate);
    let rendered = lines.join("\n");

    assert!(
        !rendered.contains("(id: 42, verified)"),
        "Should not show verified mark without online verification. Rendered: {}",
        rendered
    );
    assert!(rendered.contains("GitHub account     not verified"));
}

#[test]
fn test_format_candidate_review_lines_keeps_long_member_handles_and_hashes_inline() {
    let candidate = candidate(
        format!("{}@example.com", "release.engineering.".repeat(4)),
        Some(format!("SHA256:{}", "abcdef0123456789".repeat(8))),
        true,
        false,
        true,
        Some(format!(
            "online verification failed for {}",
            "github-response-fragment-".repeat(5)
        )),
    );

    let lines = format_candidate_review_lines(&candidate);
    let rendered = lines.join("\n");

    assert!(rendered.contains(candidate.member_handle().as_str()));
    assert!(rendered.contains("abcdef0123456789"));
    assert!(rendered.contains("github-response-fragment-"));
}

#[test]
fn test_format_failed_promotion_review_lines_keeps_long_messages_inline() {
    let candidate = candidate(
        format!("{}@example.com", "release.engineering.".repeat(4)),
        None,
        false,
        false,
        false,
        None,
    );
    let failure = PromotionReviewFailure {
        member_handle: candidate.member_handle().to_string(),
        message: format!(
            "verification failed because {}",
            "a-long-review-diagnostic-fragment-".repeat(5)
        ),
    };

    let lines = format_failed_promotion_review_lines(&[failure]);
    let rendered = lines.join("\n");

    assert!(rendered.contains("verification failed because"));
    assert!(rendered.contains("a-long-review-diagnostic-fragment-"));
}
