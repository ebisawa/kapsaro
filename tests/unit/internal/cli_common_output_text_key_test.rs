// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::{
    format_key_export_summary_lines, format_key_list_lines, is_online_verification_verified,
};
use crate::cli::common::output::key::view::{KeyInfoView, KeyListView, KeyMemberView};
use crate::cli::common::output::text::layout::{format_kid_display_text, KidDisplayFallback};
use kapsaro_core::api::online::OnlineVerificationStatus;
use std::path::PathBuf;

#[test]
fn test_display_kid_or_raw_formats_valid_kid() {
    assert_eq!(
        format_kid_display_text("KAD1AAAA1111BBBB2222CCCC3333DDDD", KidDisplayFallback::Raw),
        "KAD1-AAAA-1111-BBBB-2222-CCCC-3333-DDDD"
    );
}

#[test]
fn test_display_kid_or_raw_keeps_invalid_kid() {
    assert_eq!(
        format_kid_display_text("not-a-kid", KidDisplayFallback::Raw),
        "not-a-kid"
    );
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
fn test_format_key_list_lines_keeps_long_member_handles_and_kids_inline() {
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
                format: "kapsaro-public-key-v5",
            }],
        }],
        total_keys: 1,
    };

    let lines = format_key_list_lines(&view, true);
    let rendered = lines.join("\n");

    assert!(rendered.contains(&member_handle));
    assert!(rendered.contains(&raw_kid));
}

#[test]
fn test_format_key_export_summary_lines_keeps_long_paths_inline() {
    let member_handle = format!("{}@example.com", "release.engineering.".repeat(4));
    let raw_kid = "invalid-kid-fragment".repeat(8);
    let path = PathBuf::from(format!(
        "target/{}public-key.json",
        "very-long-directory-name/".repeat(8)
    ));

    let lines = format_key_export_summary_lines(&member_handle, &raw_kid, &path);
    let rendered = lines.join("\n");

    assert!(rendered.contains(&member_handle));
    assert!(rendered.contains(&raw_kid));
    assert!(rendered.contains(path.to_string_lossy().as_ref()));
}
