// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the local key pair expiry policy.
//! Covers signing enforcement, explicit expired-key allowance, and the rule that
//! the stricter of the private and public expiry timestamps decides the outcome.

use super::*;

/// An RFC3339 timestamp `days` from now; negative values land in the past.
fn timestamp_in_days(days: i64) -> String {
    (OffsetDateTime::now_utc() + time::Duration::days(days))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

fn private_expiry(days: i64) -> LocalKeyPairExpiry {
    LocalKeyPairExpiry::from_private_key(VerifiedExpiresAt::from_verified_private_key_metadata(
        timestamp_in_days(days),
    ))
}

fn key_pair_expiry(private_days: i64, public_days: i64) -> (LocalKeyPairExpiry, String) {
    let public_expires_at = timestamp_in_days(public_days);
    let expiry = LocalKeyPairExpiry::from_private_and_public_key(
        VerifiedExpiresAt::from_verified_private_key_metadata(timestamp_in_days(private_days)),
        VerifiedExpiresAt::from_verified_public_key_metadata(public_expires_at.clone()),
    );
    (expiry, public_expires_at)
}

// --- enforce_not_expired_for_signing ---

#[test]
fn enforce_not_expired_for_signing_accepts_valid_key() {
    assert!(private_expiry(365)
        .enforce_not_expired_for_signing()
        .is_ok());
}

#[test]
fn enforce_not_expired_for_signing_accepts_expiring_soon_key() {
    assert!(private_expiry(15).enforce_not_expired_for_signing().is_ok());
}

#[test]
fn enforce_not_expired_for_signing_rejects_expired_key() {
    let error = private_expiry(-1)
        .enforce_not_expired_for_signing()
        .unwrap_err();
    assert_eq!(error.rule(), Some("key-expiry"));
    assert!(error.to_string().contains("Local key has expired."));
}

// --- enforce_expired_usage ---

#[test]
fn enforce_expired_usage_is_silent_for_valid_key() {
    assert_eq!(
        private_expiry(365).enforce_expired_usage(false).unwrap(),
        None
    );
}

#[test]
fn enforce_expired_usage_warns_for_expiring_soon_key() {
    let warning = private_expiry(15).enforce_expired_usage(false).unwrap();
    let warning = warning.expect("expiring soon key must produce a warning");
    assert!(warning.starts_with("Local key expires in"));
    assert!(!warning.contains('\n'));
}

#[test]
fn enforce_expired_usage_rejects_expired_key_without_allowance() {
    let error = private_expiry(-1).enforce_expired_usage(false).unwrap_err();
    assert_eq!(error.rule(), Some("E_KEY_EXPIRED"));
    assert!(error.to_string().contains("Local key has expired."));
}

#[test]
fn enforce_expired_usage_allows_expired_key_when_explicitly_permitted() {
    let warning = private_expiry(-1).enforce_expired_usage(true).unwrap();
    let warning = warning.expect("allowed expired key must produce a warning");
    assert!(warning.starts_with("Local key has expired."));
    assert!(warning.contains("Reason: expired key use was explicitly allowed."));
    assert!(!warning.contains('\n'));
}

// --- build_signing_warning ---

#[test]
fn build_signing_warning_reports_expiring_soon_key() {
    let warning = private_expiry(15).build_signing_warning().unwrap();
    let warning = warning.expect("expiring soon signing key must produce a warning");
    assert!(warning.starts_with("Local key expires in"));
    assert!(!warning.contains('\n'));
}

#[test]
fn build_signing_warning_is_silent_for_expired_key() {
    assert_eq!(private_expiry(-1).build_signing_warning().unwrap(), None);
}

// --- the public key expiry participates in every decision ---

#[test]
fn expired_public_key_blocks_signing_while_private_key_is_valid() {
    let (expiry, public_expires_at) = key_pair_expiry(365, -1);
    let error = expiry.enforce_not_expired_for_signing().unwrap_err();
    assert_eq!(error.rule(), Some("key-expiry"));
    assert!(error.to_string().contains(&public_expires_at));
}

#[test]
fn nearer_public_key_expiry_drives_the_usage_warning() {
    let (expiry, public_expires_at) = key_pair_expiry(20, 5);
    let warning = expiry.enforce_expired_usage(false).unwrap();
    let warning = warning.expect("the nearer public expiry must produce a warning");
    assert!(warning.contains(&public_expires_at));
}

#[test]
fn expiring_soon_public_key_drives_the_signing_warning() {
    let (expiry, public_expires_at) = key_pair_expiry(365, 15);
    let warning = expiry.build_signing_warning().unwrap();
    let warning = warning.expect("the expiring soon public key must produce a warning");
    assert!(warning.contains(&public_expires_at));
}
