// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::feature::context::expiry::{check_key_expiry, KeyExpiryStatus};
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

// Note: write-operation helper functions require `VerifiedExpiresAt`, which is intentionally
// constructed only inside the crate. Their behavior is covered by crate unit tests in
// `src/feature/context/expiry.rs`.
