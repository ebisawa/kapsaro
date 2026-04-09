// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use secretenv::feature::context::expiry::{
    build_key_expiry_warning, build_signing_key_expiry_warning, check_key_expiry,
    enforce_key_not_expired_for_signing, KeyExpiryStatus,
};
use time::OffsetDateTime;

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

// --- check_key_expiry ---

#[test]
fn test_check_key_expiry_valid() {
    let expires_at = rfc3339(future_time(365));
    let now = OffsetDateTime::now_utc();
    let status = check_key_expiry(&expires_at, now).unwrap();
    assert!(matches!(status, KeyExpiryStatus::Valid));
}

#[test]
fn test_check_key_expiry_expiring_soon() {
    let expires_at = rfc3339(future_time(15));
    let now = OffsetDateTime::now_utc();
    let status = check_key_expiry(&expires_at, now).unwrap();
    match status {
        KeyExpiryStatus::ExpiringSoon { days_remaining, .. } => {
            assert!(days_remaining <= 30);
            assert!(days_remaining > 0);
        }
        other => panic!("Expected ExpiringSoon, got {:?}", other),
    }
}

#[test]
fn test_check_key_expiry_expired() {
    let expires_at = rfc3339(past_time(1));
    let now = OffsetDateTime::now_utc();
    let status = check_key_expiry(&expires_at, now).unwrap();
    assert!(matches!(status, KeyExpiryStatus::Expired { .. }));
}

#[test]
fn test_check_key_expiry_boundary_exactly_now() {
    // PRD: "現在時刻が expires_at を過ぎている" -> at exact boundary = expired
    let now = OffsetDateTime::now_utc();
    let expires_at = rfc3339(now);
    let status = check_key_expiry(&expires_at, now).unwrap();
    assert!(matches!(status, KeyExpiryStatus::Expired { .. }));
}

#[test]
fn test_check_key_expiry_boundary_30_days() {
    let now = OffsetDateTime::now_utc();
    // Exactly 30 days from now should be "expiring soon"
    let expires_at = rfc3339(now + time::Duration::days(30));
    let status = check_key_expiry(&expires_at, now).unwrap();
    assert!(matches!(status, KeyExpiryStatus::ExpiringSoon { .. }));
}

#[test]
fn test_check_key_expiry_boundary_31_days() {
    let now = OffsetDateTime::now_utc();
    // 31 days from now should be "valid"
    let expires_at = rfc3339(now + time::Duration::days(31));
    let status = check_key_expiry(&expires_at, now).unwrap();
    assert!(matches!(status, KeyExpiryStatus::Valid));
}

#[test]
fn test_check_key_expiry_invalid_format_fails() {
    let now = OffsetDateTime::now_utc();
    let result = check_key_expiry("not-a-date", now);
    assert!(result.is_err());
}

// --- enforce_key_not_expired_for_signing ---

#[test]
fn test_enforce_not_expired_valid() {
    let expires_at = rfc3339(future_time(365));
    assert!(enforce_key_not_expired_for_signing(&expires_at).is_ok());
}

#[test]
fn test_enforce_not_expired_expired_fails() {
    let expires_at = rfc3339(past_time(1));
    let result = enforce_key_not_expired_for_signing(&expires_at);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("expired"),
        "Error should mention expiration: {err_msg}"
    );
}

#[test]
fn test_enforce_not_expired_expiring_soon() {
    // Expiring soon should still succeed (warn only)
    let expires_at = rfc3339(future_time(15));
    assert!(enforce_key_not_expired_for_signing(&expires_at).is_ok());
}

// --- build_key_expiry_warning ---

#[test]
fn test_build_warning_expired() {
    let expires_at = rfc3339(past_time(1));
    let warning = build_key_expiry_warning(&expires_at).unwrap();
    assert!(warning.is_some());
    assert!(warning.unwrap().contains("expired"));
}

#[test]
fn test_build_warning_expiring_soon() {
    let expires_at = rfc3339(future_time(15));
    let warning = build_key_expiry_warning(&expires_at).unwrap();
    assert!(warning.is_some());
    assert!(warning.unwrap().contains("expir"));
}

#[test]
fn test_build_warning_valid_none() {
    let expires_at = rfc3339(future_time(365));
    let warning = build_key_expiry_warning(&expires_at).unwrap();
    assert!(warning.is_none());
}

#[test]
fn test_build_signing_warning_expiring_soon() {
    let expires_at = rfc3339(future_time(15));
    let warning = build_signing_key_expiry_warning(&expires_at).unwrap();
    assert!(warning.is_some());
    assert!(warning.unwrap().contains("expir"));
}

#[test]
fn test_build_signing_warning_expired_none() {
    let expires_at = rfc3339(past_time(1));
    let warning = build_signing_key_expiry_warning(&expires_at).unwrap();
    assert!(warning.is_none());
}
