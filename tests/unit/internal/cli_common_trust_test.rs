// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::cli::common::output::text::layout::visible_width;
use crate::cli::common::output::trust::review::{
    format_candidate_review_lines, format_failed_promotion_review_lines,
};
use crate::test_utils::{kid, member_handle};
use secretenv_core::cli_api::app::rewrap::promotion::PromotionReviewFailure;
use secretenv_core::cli_api::app::trust::TrustApprovalCandidate;
use secretenv_core::cli_api::test_support::storage::verify_online::VerifiedGithubIdentity;

#[test]
fn test_format_candidate_review_lines_includes_required_fields() {
    let candidate = TrustApprovalCandidate {
        member_handle: member_handle("bob@example.com"),
        kid: kid("KAD1AAAA1111BBBB2222CCCC3333DDDD"),
        fingerprint: Some("SHA256:test".to_string()),
        github_id: Some(42),
        github_login: Some("octocat".to_string()),
        attestor_pub: Some("ssh-ed25519 AAAA test".to_string()),
        verified_github: None,
        github_binding_configured: true,
        online_verification_attempted: false,
        online_verification_message: None,
        public_key: None,
        requires_out_of_band_verification: true,
    };

    let lines = format_candidate_review_lines(&candidate);
    let rendered = lines.join("\n");

    assert!(rendered.contains("member handle      bob@example.com"));
    assert!(rendered.contains("key id             KAD1-AAAA-1111-BBBB-2222-CCCC-3333-DDDD"));
    assert!(rendered.contains("SSH fingerprint    SHA256:test"));
    assert!(rendered.contains("GitHub account     not verified"));
}

#[test]
fn test_format_candidate_review_lines_warns_when_github_binding_is_missing() {
    let candidate = TrustApprovalCandidate {
        member_handle: member_handle("bob@example.com"),
        kid: kid("KAD1AAAA1111BBBB2222CCCC3333DDDD"),
        fingerprint: Some("SHA256:test".to_string()),
        github_id: None,
        github_login: None,
        attestor_pub: Some("ssh-ed25519 AAAA test".to_string()),
        verified_github: None,
        github_binding_configured: false,
        online_verification_attempted: false,
        online_verification_message: None,
        public_key: None,
        requires_out_of_band_verification: true,
    };

    let lines = format_candidate_review_lines(&candidate);
    let rendered = lines.join("\n");

    assert!(rendered.contains("key id             KAD1-AAAA-1111-BBBB-2222-CCCC-3333-DDDD"));
    assert!(rendered.contains("GitHub account     not configured"));
}

#[test]
fn test_format_candidate_review_lines_shows_github_id_without_login() {
    let candidate = TrustApprovalCandidate {
        member_handle: member_handle("bob@example.com"),
        kid: kid("KAD1AAAA1111BBBB2222CCCC3333DDDD"),
        fingerprint: None,
        github_id: Some(42),
        github_login: None,
        attestor_pub: Some("ssh-ed25519 AAAA test".to_string()),
        verified_github: None,
        github_binding_configured: true,
        online_verification_attempted: false,
        online_verification_message: None,
        public_key: None,
        requires_out_of_band_verification: true,
    };

    let lines = format_candidate_review_lines(&candidate);
    let rendered = lines.join("\n");

    assert!(rendered.contains("GitHub account     not verified"));
    assert!(!rendered.contains("verified)"));
}

#[test]
fn test_format_candidate_review_lines_warns_when_github_claim_is_unverified() {
    let candidate = TrustApprovalCandidate {
        member_handle: member_handle("bob@example.com"),
        kid: kid("KAD1AAAA1111BBBB2222CCCC3333DDDD"),
        fingerprint: Some("SHA256:test".to_string()),
        github_id: None,
        github_login: None,
        attestor_pub: Some("ssh-ed25519 AAAA test".to_string()),
        verified_github: None,
        github_binding_configured: true,
        online_verification_attempted: false,
        online_verification_message: None,
        public_key: None,
        requires_out_of_band_verification: true,
    };

    let lines = format_candidate_review_lines(&candidate);
    let rendered = lines.join("\n");

    assert!(rendered.contains("GitHub account     not verified"));
    assert!(rendered.contains("online verification was not completed"));
}

#[test]
fn test_format_candidate_review_lines_shows_online_verification_failure_message() {
    let candidate = TrustApprovalCandidate {
        member_handle: member_handle("bob@example.com"),
        kid: kid("KAD1AAAA1111BBBB2222CCCC3333DDDD"),
        fingerprint: Some("SHA256:test".to_string()),
        github_id: None,
        github_login: None,
        attestor_pub: Some("ssh-ed25519 AAAA test".to_string()),
        verified_github: None,
        github_binding_configured: true,
        online_verification_attempted: true,
        online_verification_message: Some("online verification failed".to_string()),
        public_key: None,
        requires_out_of_band_verification: true,
    };

    let lines = format_candidate_review_lines(&candidate);
    let rendered = lines.join("\n");

    assert!(rendered.contains("GitHub account     not verified (online verification failed)"));
}

#[test]
fn test_format_candidate_review_lines_shows_verified_github_mark() {
    let candidate = TrustApprovalCandidate {
        member_handle: member_handle("bob@example.com"),
        kid: kid("KAD1AAAA1111BBBB2222CCCC3333DDDD"),
        fingerprint: Some("SHA256:test".to_string()),
        github_id: Some(42),
        github_login: Some("octocat".to_string()),
        attestor_pub: Some("ssh-ed25519 AAAA test".to_string()),
        verified_github: Some(VerifiedGithubIdentity::new(
            42,
            "octocat".to_string(),
            "SHA256:test".to_string(),
            12345,
        )),
        github_binding_configured: true,
        online_verification_attempted: true,
        online_verification_message: None,
        public_key: None,
        requires_out_of_band_verification: false,
    };

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
    let candidate = TrustApprovalCandidate {
        member_handle: member_handle("bob@example.com"),
        kid: kid("KAD1AAAA1111BBBB2222CCCC3333DDDD"),
        fingerprint: Some("SHA256:test".to_string()),
        github_id: Some(42),
        github_login: Some("octocat".to_string()),
        attestor_pub: Some("ssh-ed25519 AAAA test".to_string()),
        verified_github: None,
        github_binding_configured: true,
        online_verification_attempted: false,
        online_verification_message: None,
        public_key: None,
        requires_out_of_band_verification: true,
    };

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
fn test_format_candidate_review_lines_wraps_long_member_handles_and_hashes() {
    let candidate = TrustApprovalCandidate {
        member_handle: member_handle(format!("{}@example.com", "release.engineering.".repeat(4))),
        kid: kid("KAD1AAAA1111BBBB2222CCCC3333DDDD"),
        fingerprint: Some(format!("SHA256:{}", "abcdef0123456789".repeat(8))),
        github_id: None,
        github_login: None,
        attestor_pub: Some("ssh-ed25519 AAAA test".to_string()),
        verified_github: None,
        github_binding_configured: true,
        online_verification_attempted: true,
        online_verification_message: Some(format!(
            "online verification failed for {}",
            "github-response-fragment-".repeat(5)
        )),
        public_key: None,
        requires_out_of_band_verification: true,
    };

    let lines = format_candidate_review_lines(&candidate);

    assert_line_lengths_at_most(&lines, 100);
}

#[test]
fn test_format_failed_promotion_review_lines_wraps_long_messages() {
    let candidate = TrustApprovalCandidate {
        member_handle: member_handle(format!("{}@example.com", "release.engineering.".repeat(4))),
        kid: kid("KAD1AAAA1111BBBB2222CCCC3333DDDD"),
        fingerprint: None,
        github_id: None,
        github_login: None,
        attestor_pub: Some("ssh-ed25519 AAAA test".to_string()),
        verified_github: None,
        github_binding_configured: false,
        online_verification_attempted: false,
        online_verification_message: None,
        public_key: None,
        requires_out_of_band_verification: true,
    };
    let failure = PromotionReviewFailure {
        member_handle: candidate.member_handle.to_string(),
        message: format!(
            "verification failed because {}",
            "a-long-review-diagnostic-fragment-".repeat(5)
        ),
    };

    let lines = format_failed_promotion_review_lines(&[failure]);

    assert_line_lengths_at_most(&lines, 100);
}

fn assert_line_lengths_at_most(lines: &[String], max_width: usize) {
    for line in lines {
        assert!(
            visible_width(line) <= max_width,
            "expected line to fit within {max_width} columns, got {}: {line}",
            visible_width(line)
        );
    }
}
