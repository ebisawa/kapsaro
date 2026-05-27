// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::{
    format_known_key_list_lines, format_recipient_set_list_lines,
    format_trust_purge_candidate_lines,
};
use crate::cli::common::output::trust::view::{RecipientSetListItemView, TrustListItemView};

#[test]
fn test_format_known_key_list_lines_keeps_long_member_handles_and_kids_inline() {
    let member_handle = format!("{}@example.com", "release.engineering.".repeat(4));
    let raw_kid = "invalid-kid-fragment".repeat(8);
    let item = TrustListItemView {
        kid: &raw_kid,
        member_handle: &member_handle,
        approved_at: "2026-05-01T00:00:00Z",
        approved_via: "manual-review",
    };

    let lines = format_known_key_list_lines(&[item]);
    let rendered = lines.join("\n");

    assert!(rendered.contains(&member_handle));
    assert!(rendered.contains(&raw_kid));
}

#[test]
fn test_format_recipient_set_list_lines_keeps_long_sid_hash_and_kids_inline() {
    let sid = "sid-fragment".repeat(12);
    let recipient_set_hash = format!("sha256:{}", "abcdef0123456789".repeat(10));
    let recipient_kids = vec!["invalid-kid-fragment".repeat(8)];
    let item = RecipientSetListItemView {
        sid: &sid,
        recipient_kids: &recipient_kids,
        recipient_set_hash: &recipient_set_hash,
        approved_at: "2026-05-01T00:00:00Z",
        approved_via: "manual-review",
    };

    let lines = format_recipient_set_list_lines(&[item]);
    let rendered = lines.join("\n");

    assert!(rendered.contains(&sid));
    assert!(rendered.contains(&recipient_set_hash));
    assert!(rendered.contains(&recipient_kids[0]));
}

#[test]
fn test_format_trust_purge_candidate_lines_keeps_long_values_inline() {
    let member_handle = format!("{}@example.com", "release.engineering.".repeat(4));
    let raw_kid = "invalid-kid-fragment".repeat(8);
    let item = TrustListItemView {
        kid: &raw_kid,
        member_handle: &member_handle,
        approved_at: "2026-05-01T00:00:00Z",
        approved_via: "manual-review",
    };

    let lines = format_trust_purge_candidate_lines(&[item]);
    let rendered = lines.join("\n");

    assert!(rendered.contains(&member_handle));
    assert!(rendered.contains(&raw_kid));
}
