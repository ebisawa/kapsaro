// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::io::verify_online::VerificationResult;
use crate::io::verify_online::VerifiedGithubIdentity;

fn dummy_github() -> VerifiedGithubIdentity {
    VerifiedGithubIdentity::new(1, "alice-gh".to_string(), "SHA256:abc".to_string(), 42)
}

#[test]
fn test_report_all_member_handles_returns_all_categories() {
    let report = IncomingVerificationReport {
        verified: vec![VerificationResult::verified(
            "alice",
            "OK".to_string(),
            dummy_github(),
        )],
        failed: vec![VerificationResult::failed(
            "bob",
            "Failed".to_string(),
            None,
            true,
        )],
        not_configured: vec![VerificationResult::not_configured(
            "carol",
            "No binding",
            None,
            false,
        )],
    };
    let mut ids = report.collect_member_handles();
    ids.sort();
    assert_eq!(ids, vec!["alice", "bob", "carol"]);
}

#[test]
fn test_report_verified_member_handles() {
    let report = IncomingVerificationReport {
        verified: vec![VerificationResult::verified(
            "alice",
            "OK".to_string(),
            dummy_github(),
        )],
        failed: vec![],
        not_configured: vec![],
    };
    let ids = report.collect_verified_member_handles();
    assert_eq!(ids, vec!["alice"]);
}

#[test]
fn test_report_non_failed_member_handles_excludes_failed() {
    let report = IncomingVerificationReport {
        verified: vec![VerificationResult::verified(
            "alice",
            "OK".to_string(),
            dummy_github(),
        )],
        failed: vec![VerificationResult::failed(
            "bob",
            "Failed".to_string(),
            None,
            true,
        )],
        not_configured: vec![VerificationResult::not_configured(
            "carol",
            "No binding",
            None,
            false,
        )],
    };
    let mut ids = report.collect_promotable_member_handles();
    ids.sort();
    assert_eq!(ids, vec!["alice", "carol"]);
}
