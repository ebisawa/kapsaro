// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::build_member_approval_results_output;
use crate::cli::common::output::member::view::build_member_approval_results_view;
use secretenv_core::cli_api::app::member::approval::MemberApprovalResult;

#[test]
fn test_member_approval_json_output_omits_already_known_field() {
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

    let output = build_member_approval_results_output(&view);
    let value = serde_json::to_value(output).expect("member approval output should serialize");

    let first = &value["results"][0];
    assert_eq!(first["member_handle"], "alice@example.com");
    assert!(first.get("already_known").is_none());
}
