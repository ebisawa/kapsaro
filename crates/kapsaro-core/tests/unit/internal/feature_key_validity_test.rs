// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Internal tests for the key expiry rules.
//! Covers the durations a caller can write, including ones no expiry can hold, and the
//! boundary at which an expiry counts as already reached.

use super::{enforce_expiry_after, parse_expiration};
use crate::{ErrorKind, Result};

fn parse_rfc3339(timestamp: &str) -> time::OffsetDateTime {
    time::OffsetDateTime::parse(timestamp, &time::format_description::well_known::Rfc3339).unwrap()
}

/// One creation time every case measures from, so an expiry is a value the test
/// can name rather than a span it has to compare against another run.
fn fixed_created_at() -> time::OffsetDateTime {
    parse_rfc3339("2026-03-29T12:34:56Z")
}

fn resolve_expiry(duration: &str) -> Result<time::OffsetDateTime> {
    parse_expiration(&None, &Some(duration.to_string()), fixed_created_at())
}

fn expiry_after_days(days: i64) -> time::OffsetDateTime {
    fixed_created_at() + time::Duration::days(days)
}

#[test]
fn test_parse_expiration_accepts_a_duration_in_days() {
    assert_eq!(resolve_expiry("30d").unwrap(), expiry_after_days(30));
}

#[test]
fn test_parse_expiration_reads_months_as_thirty_days() {
    assert_eq!(resolve_expiry("2m").unwrap(), expiry_after_days(60));
}

#[test]
fn test_parse_expiration_reads_years_as_365_days() {
    assert_eq!(resolve_expiry("1y").unwrap(), expiry_after_days(365));
}

/// Neither argument given leaves the default validity to decide, and it is the
/// same 365 days a caller can write out.
#[test]
fn test_parse_expiration_falls_back_to_the_default_validity() {
    let expires_at = parse_expiration(&None, &None, fixed_created_at()).unwrap();

    assert_eq!(expires_at, expiry_after_days(365));
}

/// An explicit RFC3339 expiry is taken as written.
#[test]
fn test_parse_expiration_accepts_an_explicit_expiry() {
    let expires_at = Some("2030-01-01T00:00:00Z".to_string());

    let resolved = parse_expiration(&expires_at, &None, fixed_created_at()).unwrap();

    assert_eq!(resolved, parse_rfc3339("2030-01-01T00:00:00Z"));
}

/// A unit letter outside ASCII ends the string on a multi-byte character, and
/// the count in front of it is still a number, so the refusal has to name the
/// unit rather than fail on the split.
#[test]
fn test_parse_expiration_rejects_a_non_ascii_unit_error() {
    let error = resolve_expiry("30日").unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(
        error
            .to_string()
            .contains("Expected <number><unit> with unit d, m or y"),
        "unexpected message: {error}"
    );
}

/// The count fits an `i64` but the span it names does not fit a timestamp, so
/// the refusal names the duration the caller wrote.
#[test]
fn test_parse_expiration_rejects_a_duration_past_every_expiry_error() {
    let error = resolve_expiry("99999999999999999y").unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(
        error.to_string().contains("too large"),
        "unexpected message: {error}"
    );
}

/// Days need no multiply to reach a day count, so the overflow this catches is
/// the one turning days into seconds.
#[test]
fn test_parse_expiration_rejects_a_day_count_past_every_expiry_error() {
    let error = resolve_expiry("9223372036854775807d").unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(
        error.to_string().contains("too large"),
        "unexpected message: {error}"
    );
}

#[test]
fn test_parse_expiration_rejects_an_empty_duration_error() {
    let error = resolve_expiry("   ").unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(
        error
            .to_string()
            .contains("Expected <number><unit> with unit d, m or y"),
        "unexpected message: {error}"
    );
}

#[test]
fn test_parse_expiration_rejects_a_duration_without_a_count_error() {
    let error = resolve_expiry("d").unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(
        error
            .to_string()
            .contains("Expected <number><unit> with unit d, m or y"),
        "unexpected message: {error}"
    );
}

#[test]
fn test_parse_expiration_rejects_both_expiry_arguments_error() {
    let expires_at = Some("2030-01-01T00:00:00Z".to_string());
    let valid_for = Some("30d".to_string());

    let error = parse_expiration(&expires_at, &valid_for, fixed_created_at()).unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Config);
}

/// A past `--expires-at` would let `save_generated_key` write the key pair to
/// the keystore and then fail to activate it, leaving a half-registered key
/// behind. Rejecting it here keeps the failure from ever reaching that step.
#[test]
fn test_parse_expiration_rejects_an_expiry_before_the_creation_time_error() {
    let expires_at = Some("2020-01-01T00:00:00Z".to_string());

    let error = parse_expiration(&expires_at, &None, fixed_created_at()).unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Config);
    assert!(
        error.to_string().contains("--expires-at"),
        "unexpected message: {error}"
    );
}

/// A zero-length duration resolves to an expiry at or before creation time,
/// the same half-registered-key failure mode as a past `--expires-at`.
#[test]
fn test_parse_expiration_rejects_a_zero_duration_error() {
    let error = resolve_expiry("0d").unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(
        error.to_string().contains("must be positive"),
        "unexpected message: {error}"
    );
}

#[test]
fn test_parse_expiration_rejects_a_negative_duration_error() {
    let error = resolve_expiry("-1d").unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(
        error.to_string().contains("must be positive"),
        "unexpected message: {error}"
    );
}

/// The key generation resolves its expiry at the start and stores the key after
/// the SSH and GitHub steps. An expiry reached in that window is refused here,
/// where nothing has been written yet.
#[test]
fn test_enforce_expiry_after_rejects_an_expiry_already_reached_error() {
    let now = parse_rfc3339("2026-03-29T12:34:56Z");

    let error = enforce_expiry_after("2026-03-29T12:00:00Z", now).unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Config);
    assert!(
        error.to_string().contains("already be expired"),
        "unexpected message: {error}"
    );
}

/// The keystore reads an expiry it has reached as expired and refuses to
/// activate the key, so the same instant is refused here rather than written
/// and then rejected.
#[test]
fn test_enforce_expiry_after_rejects_an_expiry_equal_to_the_current_time_error() {
    let now = parse_rfc3339("2026-03-29T12:34:56Z");

    let error = enforce_expiry_after("2026-03-29T12:34:56Z", now).unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Config);
}

#[test]
fn test_enforce_expiry_after_accepts_an_expiry_ahead_of_the_current_time() {
    let now = parse_rfc3339("2026-03-29T12:34:56Z");

    assert!(enforce_expiry_after("2026-03-29T12:34:57Z", now).is_ok());
}
