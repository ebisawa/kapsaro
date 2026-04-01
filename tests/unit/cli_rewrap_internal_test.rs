// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::app::rewrap::types::{
    IncomingGithubAccount, IncomingVerificationCategory, IncomingVerificationItem,
    IncomingVerificationReport,
};
use std::io::Cursor;

fn make_report(
    verified: Vec<IncomingVerificationItem>,
    failed: Vec<IncomingVerificationItem>,
    not_configured: Vec<IncomingVerificationItem>,
) -> IncomingVerificationReport {
    IncomingVerificationReport {
        verified,
        failed,
        not_configured,
    }
}

fn verified_result(member_id: &str) -> IncomingVerificationItem {
    IncomingVerificationItem {
        member_id: member_id.to_string(),
        category: IncomingVerificationCategory::Verified,
        message: "OK".to_string(),
        fingerprint: Some("SHA256:abc".to_string()),
        github_account: Some(IncomingGithubAccount {
            id: 12345,
            login: format!("{}-gh", member_id),
        }),
    }
}

#[test]
fn test_confirm_failed_errors() {
    let report = make_report(
        vec![],
        vec![IncomingVerificationItem {
            member_id: "bob".to_string(),
            category: IncomingVerificationCategory::Failed,
            message: "err".to_string(),
            fingerprint: None,
            github_account: None,
        }],
        vec![],
    );
    let mut input = Cursor::new(b"" as &[u8]);
    let result = confirm_incoming_promotions(&report, true, &mut input);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("Online verification failed"), "got: {}", err);
}

#[test]
fn test_confirm_not_configured_non_interactive_errors() {
    let report = make_report(
        vec![],
        vec![],
        vec![IncomingVerificationItem {
            member_id: "carol".to_string(),
            category: IncomingVerificationCategory::NotConfigured,
            message: "no github".to_string(),
            fingerprint: None,
            github_account: None,
        }],
    );
    let mut input = Cursor::new(b"" as &[u8]);
    let result = confirm_incoming_promotions(&report, false, &mut input);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("TOFU confirmation required"), "got: {}", err);
}

#[test]
fn test_confirm_not_configured_interactive_accept() {
    let report = make_report(
        vec![],
        vec![],
        vec![IncomingVerificationItem {
            member_id: "carol".to_string(),
            category: IncomingVerificationCategory::NotConfigured,
            message: "no github".to_string(),
            fingerprint: Some("SHA256:xyz".to_string()),
            github_account: None,
        }],
    );
    let mut input = Cursor::new(b"y\n" as &[u8]);
    let result = confirm_incoming_promotions(&report, true, &mut input).unwrap();
    assert_eq!(result, vec!["carol".to_string()]);
}

#[test]
fn test_confirm_not_configured_interactive_reject() {
    let report = make_report(
        vec![],
        vec![],
        vec![IncomingVerificationItem {
            member_id: "carol".to_string(),
            category: IncomingVerificationCategory::NotConfigured,
            message: "no github".to_string(),
            fingerprint: Some("SHA256:xyz".to_string()),
            github_account: None,
        }],
    );
    let mut input = Cursor::new(b"n\n" as &[u8]);
    let result = confirm_incoming_promotions(&report, true, &mut input).unwrap();
    assert!(result.is_empty());
}

#[test]
fn test_confirm_verified_and_not_configured_mixed() {
    let report = make_report(
        vec![verified_result("alice")],
        vec![],
        vec![IncomingVerificationItem {
            member_id: "carol".to_string(),
            category: IncomingVerificationCategory::NotConfigured,
            message: "no github".to_string(),
            fingerprint: Some("SHA256:xyz".to_string()),
            github_account: None,
        }],
    );
    let mut input = Cursor::new(b"y\ny\n" as &[u8]);
    let result = confirm_incoming_promotions(&report, true, &mut input).unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0], "alice");
    assert_eq!(result[1], "carol");
}

#[test]
fn test_confirm_non_tty_errors() {
    let report = make_report(vec![verified_result("alice")], vec![], vec![]);
    let mut input = Cursor::new(b"" as &[u8]);
    let result = confirm_incoming_promotions(&report, false, &mut input);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("TOFU confirmation required"), "got: {}", err);
}

#[test]
fn test_confirm_interactive_accept() {
    let report = make_report(vec![verified_result("alice")], vec![], vec![]);
    let mut input = Cursor::new(b"y\n" as &[u8]);
    let result = confirm_incoming_promotions(&report, true, &mut input).unwrap();
    assert_eq!(result, vec!["alice".to_string()]);
}

#[test]
fn test_confirm_interactive_reject() {
    let report = make_report(vec![verified_result("alice")], vec![], vec![]);
    let mut input = Cursor::new(b"n\n" as &[u8]);
    let result = confirm_incoming_promotions(&report, true, &mut input).unwrap();
    assert!(result.is_empty());
}

#[test]
fn test_confirm_interactive_mixed_responses() {
    let report = make_report(
        vec![verified_result("alice"), verified_result("bob")],
        vec![],
        vec![],
    );
    let mut input = Cursor::new(b"y\nn\n" as &[u8]);
    let result = confirm_incoming_promotions(&report, true, &mut input).unwrap();
    assert_eq!(result, vec!["alice".to_string()]);
}

#[test]
fn test_confirm_empty_report() {
    let report = make_report(vec![], vec![], vec![]);
    let mut input = Cursor::new(b"" as &[u8]);
    let result = confirm_incoming_promotions(&report, true, &mut input).unwrap();
    assert!(result.is_empty());
}
