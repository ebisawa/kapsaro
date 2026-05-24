// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::{
    display_kid_or_raw, format_key_export_summary_lines, format_key_list_lines,
    is_online_verification_verified,
};
use crate::cli::common::output::key::view::{KeyInfoView, KeyListView, KeyMemberView};
use crate::cli::common::output::text::layout::visible_width;
use secretenv_core::api::online::OnlineVerificationStatus;
use std::path::PathBuf;

#[test]
fn test_display_kid_or_raw_formats_valid_kid() {
    assert_eq!(
        display_kid_or_raw("KAD1AAAA1111BBBB2222CCCC3333DDDD"),
        "KAD1-AAAA-1111-BBBB-2222-CCCC-3333-DDDD"
    );
}

#[test]
fn test_display_kid_or_raw_keeps_invalid_kid() {
    assert_eq!(display_kid_or_raw("not-a-kid"), "not-a-kid");
}

#[test]
fn test_is_online_verification_verified_only_accepts_verified_status() {
    assert!(is_online_verification_verified(
        OnlineVerificationStatus::Verified
    ));
    assert!(!is_online_verification_verified(
        OnlineVerificationStatus::NotConfigured
    ));
    assert!(!is_online_verification_verified(
        OnlineVerificationStatus::Failed
    ));
}

#[test]
fn test_format_key_list_lines_wraps_long_member_handles_and_kids() {
    let member_handle = format!("{}@example.com", "release.engineering.".repeat(4));
    let raw_kid = "invalid-kid-fragment".repeat(8);
    let view = KeyListView {
        entries: vec![KeyMemberView {
            member_handle: &member_handle,
            keys: vec![KeyInfoView {
                kid: &raw_kid,
                member_handle: &member_handle,
                created_at: "2026-05-01T00:00:00Z",
                expires_at: "2027-05-01T00:00:00Z",
                active: true,
                format: "secretenv-public-key-v5",
            }],
        }],
        total_keys: 1,
    };

    let lines = format_key_list_lines(&view, true);

    assert_line_lengths_at_most(&lines, 100);
}

#[test]
fn test_format_key_export_summary_lines_wraps_long_paths() {
    let member_handle = format!("{}@example.com", "release.engineering.".repeat(4));
    let raw_kid = "invalid-kid-fragment".repeat(8);
    let path = PathBuf::from(format!(
        "target/{}public-key.json",
        "very-long-directory-name/".repeat(8)
    ));

    let lines = format_key_export_summary_lines(&member_handle, &raw_kid, &path);

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
