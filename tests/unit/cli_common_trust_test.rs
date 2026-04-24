// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::trust::TrustApprovalCandidate;
use crate::cli::common::output::trust::review::format_candidate_review_lines;
use crate::io::verify_online::VerifiedGithubIdentity;
use crate::test_utils::{kid, member_id};

#[test]
fn test_format_candidate_review_lines_includes_required_fields() {
    let candidate = TrustApprovalCandidate {
        member_id: member_id("bob@example.com"),
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
        !rendered.contains("member_id:"),
        "member_id is shown in the header, not in detail lines"
    );
    assert!(rendered.contains("kid: KAD1-AAAA-1111-BBBB-2222-CCCC-3333-DDDD"));
    assert!(rendered.contains("attestation fingerprint: SHA256:test"));
    assert!(rendered.contains("GitHub account id: 42 (octocat)"));
    assert!(rendered.contains("This key is not yet trusted"));
}

#[test]
fn test_format_candidate_review_lines_warns_when_github_binding_is_missing() {
    let candidate = TrustApprovalCandidate {
        member_id: member_id("bob@example.com"),
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

    assert!(rendered.contains("kid: KAD1-AAAA-1111-BBBB-2222-CCCC-3333-DDDD"));
    assert!(rendered.contains("online verification could not be performed"));
}

#[test]
fn test_format_candidate_review_lines_shows_github_id_without_login() {
    let candidate = TrustApprovalCandidate {
        member_id: member_id("bob@example.com"),
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

    assert!(rendered.contains("GitHub account id: 42"));
    assert!(!rendered.contains("(octocat)"));
}

#[test]
fn test_format_candidate_review_lines_warns_when_github_claim_is_unverified() {
    let candidate = TrustApprovalCandidate {
        member_id: member_id("bob@example.com"),
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

    assert!(rendered.contains("did not verify it online"));
}

#[test]
fn test_format_candidate_review_lines_shows_online_verification_failure_message() {
    let candidate = TrustApprovalCandidate {
        member_id: member_id("bob@example.com"),
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

    assert!(rendered.contains("online verification failed"));
}

#[test]
fn test_format_candidate_review_lines_shows_verified_github_mark() {
    let candidate = TrustApprovalCandidate {
        member_id: member_id("bob@example.com"),
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

    assert!(
        rendered.contains("verified"),
        "Should show verified mark when online verification succeeded. Rendered: {}",
        rendered
    );
    assert!(
        !rendered.contains("not yet trusted"),
        "Should not show untrusted warning when verified. Rendered: {}",
        rendered
    );
}

#[test]
fn test_format_candidate_review_lines_no_verified_mark_without_online_verification() {
    let candidate = TrustApprovalCandidate {
        member_id: member_id("bob@example.com"),
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
        !rendered.contains("verified"),
        "Should not show verified mark without online verification. Rendered: {}",
        rendered
    );
}
