// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::cli::common::output::member::view::{
    build_member_approval_results_view, build_member_list_view,
};
use kapsaro_core::api::member::approval::MemberApprovalResult;
use kapsaro_core::api::member::types::{MemberListEntry, MemberListResult};

#[test]
fn test_build_member_list_view_preserves_kid() {
    let result = MemberListResult {
        active: vec![MemberListEntry {
            member_handle: "alice@example.com".to_string(),
            kid: "KAD1AAAA1111BBBB2222CCCC3333DDDD".to_string(),
            document: serde_json::json!({}),
        }],
        incoming: vec![MemberListEntry {
            member_handle: "bob@example.com".to_string(),
            kid: "KBD2AAAA1111BBBB2222CCCC3333DDDD".to_string(),
            document: serde_json::json!({}),
        }],
        warnings: Vec::new(),
    };

    let view = build_member_list_view(&result);

    assert_eq!(view.active[0].kid, "KAD1AAAA1111BBBB2222CCCC3333DDDD");
    assert_eq!(view.incoming[0].kid, "KBD2AAAA1111BBBB2222CCCC3333DDDD");
}

#[test]
fn test_build_member_approval_results_view_preserves_review_fields() {
    let result = MemberApprovalResult {
        member_handle: "alice@example.com".to_string(),
        kid: "A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1".to_string(),
        verified: true,
        approved: false,
        review_required: true,
        already_known: false,
        message: "verified".to_string(),
        fingerprint: Some("SHA256:test".to_string()),
        github_id: Some(42),
        github_login: Some("alice-gh".to_string()),
        github_binding_configured: true,
        attestor_pub: Some("ssh-ed25519 AAAA test".to_string()),
        verified_github: None,
    };

    let view = build_member_approval_results_view(std::slice::from_ref(&result));

    assert_eq!(view.results.len(), 1);
    assert_eq!(view.results[0].member_handle, result.member_handle);
    assert_eq!(view.results[0].kid, result.kid);
    assert_eq!(view.results[0].fingerprint, result.fingerprint.as_deref());
    assert_eq!(view.results[0].github_id, result.github_id);
    assert_eq!(view.results[0].github_login, result.github_login.as_deref());
}

#[test]
fn test_build_member_approval_results_view_skips_already_known_results() {
    let known_result = MemberApprovalResult {
        member_handle: "alice@example.com".to_string(),
        kid: "A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1".to_string(),
        verified: true,
        approved: false,
        review_required: false,
        already_known: true,
        message: "verified".to_string(),
        fingerprint: Some("SHA256:known".to_string()),
        github_id: Some(42),
        github_login: Some("alice-gh".to_string()),
        github_binding_configured: true,
        attestor_pub: Some("ssh-ed25519 AAAA known".to_string()),
        verified_github: None,
    };
    let new_result = MemberApprovalResult {
        member_handle: "bob@example.com".to_string(),
        kid: "B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2".to_string(),
        verified: true,
        approved: false,
        review_required: true,
        already_known: false,
        message: "verified".to_string(),
        fingerprint: Some("SHA256:new".to_string()),
        github_id: Some(7),
        github_login: Some("bob-gh".to_string()),
        github_binding_configured: true,
        attestor_pub: Some("ssh-ed25519 AAAA new".to_string()),
        verified_github: None,
    };

    let results = [known_result, new_result];
    let view = build_member_approval_results_view(&results);

    assert_eq!(view.results.len(), 1);
    assert_eq!(view.results[0].member_handle, "bob@example.com");
    assert!(view
        .results
        .iter()
        .all(|result| result.member_handle != "alice@example.com"));
}
