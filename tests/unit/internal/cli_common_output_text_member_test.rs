// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::{
    format_member_approval_results_lines, format_member_list_lines, format_member_show_lines,
    format_member_verification_results_lines,
};
use crate::cli::common::output::member::view::{
    MemberApprovalItemView, MemberApprovalResultsView, MemberGithubClaimView, MemberListEntryView,
    MemberListView, MemberShowView, MemberVerificationItemView, MemberVerificationResultsView,
};
use crate::test_utils::StdoutColorGuard;
use serde_json::json;
use serial_test::serial;

#[test]
fn test_format_member_list_lines_renders_dashed_kids() {
    let document = json!({});
    let view = MemberListView {
        active: vec![MemberListEntryView {
            member_handle: "alice@example.com",
            kid: "KAD1AAAA1111BBBB2222CCCC3333DDDD",
            document: &document,
        }],
        incoming: vec![MemberListEntryView {
            member_handle: "bob@example.com",
            kid: "KBD2AAAA1111BBBB2222CCCC3333DDDD",
            document: &document,
        }],
        warnings: &[],
    };

    let rendered = format_member_list_lines(&view).join("\n");

    assert!(rendered.contains("Active:\n"));
    assert!(rendered.contains("alice@example.com  KAD1-AAAA-1111-BBBB-2222-CCCC-3333-DDDD"));
    assert!(rendered.contains("Incoming:\n"));
    assert!(rendered.contains("bob@example.com    KBD2-AAAA-1111-BBBB-2222-CCCC-3333-DDDD"));
}

#[test]
fn test_format_member_list_lines_keeps_long_handles_inline() {
    let document = json!({});
    let long_handle = format!("{}@example.com", "a".repeat(116));
    let view = MemberListView {
        active: vec![MemberListEntryView {
            member_handle: &long_handle,
            kid: "KAD1AAAA1111BBBB2222CCCC3333DDDD",
            document: &document,
        }],
        incoming: vec![],
        warnings: &[],
    };

    let lines = format_member_list_lines(&view);

    assert!(lines.iter().any(|line| {
        line.contains(&long_handle) && line.contains("KAD1-AAAA-1111-BBBB-2222-CCCC-3333-DDDD")
    }));
}

#[test]
fn test_format_member_list_lines_keeps_long_member_handle_and_dashed_kid_inline() {
    let document = json!({});
    let member_handle = "avery.long.member.handle.for.release.engineering@example.com";
    let kid = "KAD1-AAAA-1111-BBBB-2222-CCCC-3333-DDDD";
    let view = MemberListView {
        active: vec![MemberListEntryView {
            member_handle,
            kid: "KAD1AAAA1111BBBB2222CCCC3333DDDD",
            document: &document,
        }],
        incoming: vec![],
        warnings: &[],
    };

    let lines = format_member_list_lines(&view);
    let rendered = lines.join("\n");

    assert!(rendered.contains(&format!("{member_handle}  {kid}")));
}

#[test]
#[serial]
fn test_format_member_show_lines_renders_header_and_status_section() {
    let _guard = StdoutColorGuard::new(false);
    let view = build_member_show_view(None);

    let rendered = format_member_show_lines(&view).join("\n");

    assert!(
        rendered.contains("\u{25CF} alice@example.com"),
        "expected bullet header, got:\n{rendered}"
    );
    assert!(rendered.contains("Status\n"));
    assert!(rendered.contains("  Membership  : active"));
    assert!(rendered.contains("  Verification: valid"));
    assert!(
        rendered.contains("Key  KAD1-AAAA-1111-BBBB-2222-CCCC-3333-DDDD"),
        "expected Key title with dashed kid, got:\n{rendered}"
    );
    assert!(rendered.contains("  Algorithm   : X25519 + Ed25519"));
    assert!(rendered.contains("  Expires At  : 2027-01-14T00:00:00Z"));
    assert!(rendered.contains("  Created At  : 2026-01-14T00:00:00Z"));
    assert!(rendered.contains("SSH Attestation\n"));
    assert!(rendered.contains("  Fingerprint : SHA256:TESTFINGERPRINT"));
    assert!(!rendered.contains("ssh-ed25519"));
    assert!(!rendered.contains("Public Key"));
    assert!(!rendered.contains("Method"));
    assert!(!rendered.contains("GitHub Binding"));
}

#[test]
#[serial]
fn test_format_member_show_lines_includes_github_binding_section() {
    let _guard = StdoutColorGuard::new(false);
    let view = build_member_show_view(Some(MemberGithubClaimView {
        id: 42,
        login: "octocat",
    }));

    let rendered = format_member_show_lines(&view).join("\n");

    assert!(rendered.contains("GitHub Binding\n"));
    assert!(rendered.contains("  octocat (id: 42)"));
}

#[test]
#[serial]
fn test_format_member_show_lines_keeps_long_rows_inline() {
    let _guard = StdoutColorGuard::new(false);
    let long_fingerprint = format!("SHA256:{}", "abcdef0123456789".repeat(8));
    let view = MemberShowView {
        member_handle: Box::leak(
            format!("{}@example.com", "release.engineering.".repeat(5)).into_boxed_str(),
        ),
        kid: "KAD1AAAA1111BBBB2222CCCC3333DDDD",
        expires_at: "2027-01-14T00:00:00Z",
        created_at: Some("2026-01-14T00:00:00Z"),
        algorithm: "X25519 + Ed25519".to_string(),
        ssh_fingerprint: Box::leak(long_fingerprint.into_boxed_str()),
        github_claim: Some(MemberGithubClaimView {
            id: 42,
            login: "octocat",
        }),
        verification_status: "valid",
        membership_status: "active",
        verification_warnings: &[],
        document: Box::leak(Box::new(json!({}))),
    };

    let lines = format_member_show_lines(&view);
    let rendered = lines.join("\n");

    assert!(lines.iter().any(|line| line.starts_with("\u{25CF} ")));
    assert!(rendered.contains("  Fingerprint : SHA256:"));
}

#[test]
#[serial]
fn test_format_member_verification_results_keeps_long_handle_message_and_fingerprint_inline() {
    let _guard = StdoutColorGuard::new(false);
    let member_handle = format!("{}@example.com", "release.engineering.".repeat(5));
    let message = format!(
        "GitHub verification could not confirm the configured login because {}",
        "the response did not include a matching SSH signing key ".repeat(3)
    );
    let fingerprint = format!("SHA256:{}", "abcdef0123456789".repeat(8));
    let view = MemberVerificationResultsView {
        results: vec![MemberVerificationItemView {
            member_handle: &member_handle,
            verified: false,
            message: &message,
            fingerprint: Some(&fingerprint),
            matched_key_id: None,
        }],
    };

    let lines = format_member_verification_results_lines(&view);
    let rendered = lines.join("\n");

    assert!(rendered.contains(&member_handle));
    assert!(rendered.contains(&message));
    assert!(rendered.contains(&fingerprint));
    assert!(lines.iter().any(|line| line == "Verified 0/1 members"));
}

#[test]
#[serial]
fn test_format_member_approval_results_keeps_long_handle_and_message_inline() {
    let _guard = StdoutColorGuard::new(false);
    let member_handle = format!("{}@example.com", "incoming.release.".repeat(5));
    let message = format!(
        "manual review is required because {}",
        "the online verification result was unavailable ".repeat(4)
    );
    let result = build_member_approval_item_view(&member_handle, &message);
    let view = MemberApprovalResultsView {
        results: vec![result],
    };

    let lines = format_member_approval_results_lines(&view);
    let rendered = lines.join("\n");

    assert!(rendered.contains(&member_handle));
    assert!(rendered.contains(&message));
    assert!(lines.iter().any(|line| line == "Approved 0/1 members"));
}

#[test]
fn test_format_member_approval_results_shows_verified_github_account_id() {
    let view = MemberApprovalResultsView {
        results: vec![MemberApprovalItemView {
            member_handle: "bob@example.com",
            kid: "A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1",
            verified: true,
            approved: true,
            review_required: true,
            message: "verified",
            fingerprint: Some("SHA256:test"),
            github_id: Some(42),
            github_login: Some("octocat"),
            github_binding_configured: true,
        }],
    };

    let rendered = format_member_approval_results_lines(&view).join("\n");

    assert!(rendered.contains("GitHub account     octocat (id: 42, verified)"));
}

#[test]
fn test_format_member_approval_results_shows_verified_github_id_without_login() {
    let view = MemberApprovalResultsView {
        results: vec![MemberApprovalItemView {
            member_handle: "bob@example.com",
            kid: "A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1",
            verified: true,
            approved: true,
            review_required: true,
            message: "verified",
            fingerprint: Some("SHA256:test"),
            github_id: Some(42),
            github_login: None,
            github_binding_configured: true,
        }],
    };

    let rendered = format_member_approval_results_lines(&view).join("\n");

    assert!(rendered.contains("GitHub account     id: 42 (verified)"));
}

#[test]
fn test_format_member_approval_results_distinguishes_unverified_and_unconfigured() {
    let mut configured = build_member_approval_item_view("bob@example.com", "not verified");
    configured.github_binding_configured = true;
    let unconfigured = build_member_approval_item_view("carol@example.com", "manual review");
    let view = MemberApprovalResultsView {
        results: vec![configured, unconfigured],
    };

    let rendered = format_member_approval_results_lines(&view).join("\n");

    assert!(rendered.contains("GitHub account     not verified"));
    assert!(rendered.contains("GitHub account     not configured"));
}

fn build_member_show_view(
    github_claim: Option<MemberGithubClaimView<'static>>,
) -> MemberShowView<'static> {
    MemberShowView {
        member_handle: "alice@example.com",
        kid: "KAD1AAAA1111BBBB2222CCCC3333DDDD",
        expires_at: "2027-01-14T00:00:00Z",
        created_at: Some("2026-01-14T00:00:00Z"),
        algorithm: "X25519 + Ed25519".to_string(),
        ssh_fingerprint: "SHA256:TESTFINGERPRINT",
        github_claim,
        verification_status: "valid",
        membership_status: "active",
        verification_warnings: &[],
        document: Box::leak(Box::new(json!({}))),
    }
}

fn build_member_approval_item_view<'a>(
    member_handle: &'a str,
    message: &'a str,
) -> MemberApprovalItemView<'a> {
    MemberApprovalItemView {
        member_handle,
        kid: "A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1",
        verified: false,
        approved: false,
        review_required: true,
        message,
        fingerprint: Some("SHA256:test"),
        github_id: None,
        github_login: None,
        github_binding_configured: false,
    }
}
