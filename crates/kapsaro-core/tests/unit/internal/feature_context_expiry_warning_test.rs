// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for key expiry warning construction.
//! Covers the wording thresholds for decryption and signing keys.

use super::*;

fn rfc3339(dt: OffsetDateTime) -> String {
    dt.format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

fn future_time(days: i64) -> OffsetDateTime {
    let now = OffsetDateTime::now_utc();
    now + time::Duration::days(days)
}

fn past_time(days: i64) -> OffsetDateTime {
    let now = OffsetDateTime::now_utc();
    now - time::Duration::days(days)
}

#[test]
fn enforce_not_expired_valid() {
    let expires_at =
        VerifiedExpiresAt::from_verified_private_key_metadata(rfc3339(future_time(365)));
    assert!(enforce_key_not_expired_for_signing(&expires_at).is_ok());
}

#[test]
fn enforce_not_expired_expired_fails() {
    let expires_at = VerifiedExpiresAt::from_verified_private_key_metadata(rfc3339(past_time(1)));
    let result = enforce_key_not_expired_for_signing(&expires_at);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("expired"));
}

#[test]
fn enforce_not_expired_expiring_soon_ok() {
    let expires_at =
        VerifiedExpiresAt::from_verified_private_key_metadata(rfc3339(future_time(15)));
    assert!(enforce_key_not_expired_for_signing(&expires_at).is_ok());
}

#[test]
fn build_warning_expired() {
    let expires_at = VerifiedExpiresAt::from_verified_private_key_metadata(rfc3339(past_time(1)));
    let warning = build_key_expiry_warning(&expires_at).unwrap();
    assert!(warning.is_some());
    let warning = warning.unwrap();
    assert!(warning.contains("expired"));
    assert!(!warning.contains('\n'));
}

#[test]
fn build_warning_expiring_soon() {
    let expires_at =
        VerifiedExpiresAt::from_verified_private_key_metadata(rfc3339(future_time(15)));
    let warning = build_key_expiry_warning(&expires_at).unwrap();
    assert!(warning.is_some());
    let warning = warning.unwrap();
    assert!(warning.contains("expir"));
    assert!(!warning.contains('\n'));
}

#[test]
fn build_warning_valid_none() {
    let expires_at =
        VerifiedExpiresAt::from_verified_private_key_metadata(rfc3339(future_time(365)));
    let warning = build_key_expiry_warning(&expires_at).unwrap();
    assert!(warning.is_none());
}

#[test]
fn build_signing_warning_expiring_soon() {
    let expires_at =
        VerifiedExpiresAt::from_verified_private_key_metadata(rfc3339(future_time(15)));
    let warning = build_signing_key_expiry_warning(&expires_at).unwrap();
    assert!(warning.is_some());
    let warning = warning.unwrap();
    assert!(warning.contains("expir"));
    assert!(!warning.contains('\n'));
}

#[test]
fn build_signing_warning_expired_none() {
    let expires_at = VerifiedExpiresAt::from_verified_private_key_metadata(rfc3339(past_time(1)));
    let warning = build_signing_key_expiry_warning(&expires_at).unwrap();
    assert!(warning.is_none());
}
