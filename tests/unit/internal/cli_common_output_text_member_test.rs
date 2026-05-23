// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::{format_member_list_lines, format_member_show_lines};
use crate::cli::common::output::member::view::{
    MemberGithubClaimView, MemberListEntryView, MemberListView, MemberShowView,
};
use console::{colors_enabled, set_colors_enabled};
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
