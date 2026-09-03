// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Internal tests for key expiry resolution from CLI arguments.
//! Covers the durations a caller can type, including ones no expiry can hold.

use super::{ensure_expiry_after, ensure_expiry_not_reached};
use crate::service::key::timestamp::resolve_key_timestamps;
use crate::ErrorKind;

fn valid_for(duration: &str) -> Option<String> {
    Some(duration.to_string())
}

fn parse_rfc3339(timestamp: &str) -> time::OffsetDateTime {
    time::OffsetDateTime::parse(timestamp, &time::format_description::well_known::Rfc3339).unwrap()
}

/// How far one resolved expiry sits from the creation time recorded with it.
///
/// Two runs never share a clock reading, so comparing the spans each run
/// produced is what states that two durations mean the same length of time.
fn expiry_span(duration: &str) -> time::Duration {
    let (created_at, expires_at) = resolve_key_timestamps(&None, &valid_for(duration)).unwrap();

    parse_rfc3339(&expires_at) - parse_rfc3339(&created_at)
}

#[test]
fn test_resolve_key_timestamps_accepts_a_duration_in_days() {
    assert_eq!(expiry_span("30d"), time::Duration::days(30));
}

#[test]
fn test_resolve_key_timestamps_reads_months_as_thirty_days() {
    assert_eq!(expiry_span("2m"), expiry_span("60d"));
}

#[test]
fn test_resolve_key_timestamps_reads_years_as_365_days() {
    assert_eq!(expiry_span("1y"), expiry_span("365d"));
}

/// A unit letter outside ASCII ends the string on a multi-byte character, and
/// the count in front of it is still a number, so the refusal has to name the
/// unit rather than fail on the split.
#[test]
fn test_resolve_key_timestamps_rejects_a_non_ascii_unit() {
    let error = resolve_key_timestamps(&None, &valid_for("30日")).unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(
        error.to_string().contains("Invalid duration unit"),
        "unexpected message: {error}"
    );
}

/// The count fits an `i64` but the span it names does not fit a timestamp, so
/// the refusal names the duration the caller wrote.
#[test]
fn test_resolve_key_timestamps_rejects_a_duration_past_every_expiry() {
    let error = resolve_key_timestamps(&None, &valid_for("99999999999999999y")).unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(
        error.to_string().contains("too large"),
        "unexpected message: {error}"
    );
}

/// Days need no multiply to reach a day count, so the overflow this catches is
/// the one turning days into seconds.
#[test]
fn test_resolve_key_timestamps_rejects_a_day_count_past_every_expiry() {
    let error = resolve_key_timestamps(&None, &valid_for("9223372036854775807d")).unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(
        error.to_string().contains("too large"),
        "unexpected message: {error}"
    );
}

#[test]
fn test_resolve_key_timestamps_rejects_an_empty_duration() {
    let error = resolve_key_timestamps(&None, &valid_for("   ")).unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(
        error.to_string().contains("Empty duration"),
        "unexpected message: {error}"
    );
}

#[test]
fn test_resolve_key_timestamps_rejects_a_duration_without_a_count() {
    let error = resolve_key_timestamps(&None, &valid_for("d")).unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(
        error.to_string().contains("Invalid duration number"),
        "unexpected message: {error}"
    );
}

#[test]
fn test_resolve_key_timestamps_rejects_both_expiry_arguments() {
    let expires_at = Some("2030-01-01T00:00:00Z".to_string());
    let error = resolve_key_timestamps(&expires_at, &valid_for("30d")).unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Config);
}

/// A past `--expires-at` would let `save_generated_key` write the key pair to
/// the keystore and then fail to activate it, leaving a half-registered key
/// behind. Rejecting it here keeps the failure from ever reaching that step.
#[test]
fn test_resolve_key_timestamps_rejects_an_expiry_in_the_past() {
    let expires_at = Some("2020-01-01T00:00:00Z".to_string());
    let error = resolve_key_timestamps(&expires_at, &None).unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Config);
    assert!(
        error.to_string().contains("--expires-at"),
        "unexpected message: {error}"
    );
}

/// A zero-length duration resolves to an expiry at or before creation time,
/// the same half-registered-key failure mode as a past `--expires-at`.
#[test]
fn test_resolve_key_timestamps_rejects_a_zero_duration() {
    let error = resolve_key_timestamps(&None, &valid_for("0d")).unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(
        error.to_string().contains("must be positive"),
        "unexpected message: {error}"
    );
}

#[test]
fn test_resolve_key_timestamps_rejects_a_negative_duration() {
    let error = resolve_key_timestamps(&None, &valid_for("-1d")).unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(
        error.to_string().contains("must be positive"),
        "unexpected message: {error}"
    );
}

/// An expiry still ahead of the moment the key is stored is what the keystore
/// accepts, so the check that runs just before the write accepts it too.
#[test]
fn test_a_resolved_expiry_is_still_ahead_when_the_key_is_stored() {
    let (_created_at, expires_at) = resolve_key_timestamps(&None, &valid_for("30d")).unwrap();

    assert!(ensure_expiry_not_reached(&expires_at).is_ok());
}

/// The key generation resolves its expiry at the start and stores the key after
/// the SSH and GitHub steps. An expiry reached in that window is refused here,
/// where nothing has been written yet.
#[test]
fn test_an_expiry_reached_before_the_key_is_stored_is_refused() {
    let now = parse_rfc3339("2026-03-29T12:34:56Z");

    let error = ensure_expiry_after("2026-03-29T12:00:00Z", now).unwrap_err();

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
fn test_an_expiry_equal_to_the_current_time_is_refused() {
    let now = parse_rfc3339("2026-03-29T12:34:56Z");

    let error = ensure_expiry_after("2026-03-29T12:34:56Z", now).unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Config);
}

#[test]
fn test_an_expiry_ahead_of_the_current_time_is_accepted() {
    let now = parse_rfc3339("2026-03-29T12:34:56Z");

    assert!(ensure_expiry_after("2026-03-29T12:34:57Z", now).is_ok());
}
