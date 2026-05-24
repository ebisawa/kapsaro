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
use crate::cli::common::output::text::layout::visible_width;
use console::{colors_enabled, set_colors_enabled};
use secretenv_core::cli_api::app::member::approval::MemberApprovalResult;
use secretenv_core::cli_api::app::trust::TrustApprovalCandidate;
use serde_json::json;
use serial_test::serial;

struct StdoutColorGuard {
    enabled: bool,
}

impl StdoutColorGuard {
    fn new(enabled: bool) -> Self {
        let previous = colors_enabled();
        set_colors_enabled(enabled);
        Self { enabled: previous }
    }
}

impl Drop for StdoutColorGuard {
    fn drop(&mut self) {
        set_colors_enabled(self.enabled);
    }
}

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
fn test_format_member_list_lines_keeps_long_handles_within_terminal_width() {
    let document = json!({});
    let long_handle = format!("{}@example.com", "a".repeat(120));
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

    assert!(lines.iter().all(|line| visible_width(line) <= 100));
    assert!(lines
        .iter()
        .any(|line| line.trim_start() == "KAD1-AAAA-1111-BBBB-2222-CCCC-3333-DDDD"));
}

#[test]
fn test_format_member_list_lines_wraps_long_member_handle_and_dashed_kid() {
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

    assert_line_lengths_at_most(&lines, 100);
    assert!(!rendered.contains(&format!("{member_handle}  {kid}")));
    assert!(lines
        .iter()
        .any(|line| line == &format!("  {member_handle}")));
    assert!(lines.iter().any(|line| line.trim_start() == kid));
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
}

#[test]
#[serial]
fn test_format_member_show_lines_renders_key_section_with_kid_in_title() {
    let _guard = StdoutColorGuard::new(false);
    let view = build_member_show_view(None);

    let rendered = format_member_show_lines(&view).join("\n");

    assert!(
        rendered.contains("Key  KAD1-AAAA-1111-BBBB-2222-CCCC-3333-DDDD"),
        "expected Key title with dashed kid, got:\n{rendered}"
    );
    assert!(rendered.contains("  Algorithm   : X25519 + Ed25519"));
    assert!(rendered.contains("  Expires At  : 2027-01-14T00:00:00Z"));
    assert!(rendered.contains("  Created At  : 2026-01-14T00:00:00Z"));
}

#[test]
#[serial]
fn test_format_member_show_lines_renders_ssh_attestation_fingerprint_only() {
    let _guard = StdoutColorGuard::new(false);
    let view = build_member_show_view(None);

    let rendered = format_member_show_lines(&view).join("\n");

    assert!(rendered.contains("SSH Attestation\n"));
    assert!(rendered.contains("  Fingerprint : SHA256:TESTFINGERPRINT"));
    assert!(!rendered.contains("ssh-ed25519"));
    assert!(!rendered.contains("Public Key"));
    assert!(!rendered.contains("Method"));
}

#[test]
#[serial]
fn test_format_member_show_lines_omits_github_binding_when_absent() {
    let _guard = StdoutColorGuard::new(false);
    let view = build_member_show_view(None);

    let rendered = format_member_show_lines(&view).join("\n");

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
fn test_format_member_show_lines_wraps_long_rows() {
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

    assert_line_lengths_at_most(&lines, 100);
    assert!(lines.iter().any(|line| line.starts_with("\u{25CF} ")));
    assert!(lines
        .iter()
        .any(|line| line.starts_with("  Fingerprint : ")));
}

#[test]
#[serial]
fn test_format_member_verification_results_wraps_long_handle_message_and_fingerprint() {
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

    assert_line_lengths_at_most(&lines, 100);
    assert!(lines
        .iter()
        .any(|line| line.trim_start().starts_with("SSH key fingerprint:")));
    assert!(lines.iter().any(|line| line == "Verified 0/1 members"));
}

#[test]
#[serial]
fn test_format_member_approval_results_wraps_long_handle_and_message() {
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

    assert_line_lengths_at_most(&lines, 100);
    assert!(lines.iter().any(|line| line == "Approved 0/1 members"));
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
    let result = MemberApprovalResult {
        member_handle: member_handle.to_string(),
        kid: "A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1".to_string(),
        verified: false,
        approved: false,
        review_required: true,
        already_known: false,
        message: message.to_string(),
        fingerprint: Some("SHA256:test".to_string()),
        github_id: None,
        github_login: None,
        github_binding_configured: false,
        attestor_pub: Some("ssh-ed25519 AAAA test".to_string()),
        verified_github: None,
    };
    let review_candidate = TrustApprovalCandidate::from(&result);

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
        review_candidate,
    }
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
