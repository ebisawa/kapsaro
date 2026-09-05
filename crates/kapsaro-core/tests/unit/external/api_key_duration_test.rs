// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! External tests for the relative duration the key and trust commands share.
//! Fixes the units accepted and the spans no expiry can hold.

use kapsaro_core::api::key::parse_relative_duration_days;
use kapsaro_core::ErrorKind;

/// The duration `--valid-for` and `--older-than` share resolves to a day count,
/// so the two commands read the same units the same way.
#[test]
fn test_parse_relative_duration_days_reads_each_unit() {
    assert_eq!(parse_relative_duration_days("30d").unwrap(), 30);
    assert_eq!(parse_relative_duration_days("2m").unwrap(), 60);
    assert_eq!(parse_relative_duration_days("1y").unwrap(), 365);
}

#[test]
fn test_parse_relative_duration_days_rejects_an_unknown_unit_error() {
    let error = parse_relative_duration_days("1w").unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(
        error
            .to_string()
            .contains("Expected <number><unit> with unit d, m or y"),
        "unexpected message: {error}"
    );
}

/// A day count callers turn into a `time::Duration` has to survive the multiply
/// by seconds-per-day that the conversion performs, and that multiply panics on
/// overflow rather than reporting one. Refusing the span here is what keeps the
/// panic out of reach.
#[test]
fn test_parse_relative_duration_days_rejects_a_span_past_every_duration_error() {
    let error = parse_relative_duration_days("300000000000y").unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(
        error.to_string().contains("too large"),
        "unexpected message: {error}"
    );
}

/// The largest span that still converts is accepted, so the refusal above is the
/// overflow itself rather than a bound drawn short of it.
#[test]
fn test_parse_relative_duration_days_accepts_the_largest_convertible_span() {
    const SECONDS_PER_DAY: i64 = 86_400;
    let largest_days = i64::MAX / SECONDS_PER_DAY;

    let days = parse_relative_duration_days(&format!("{largest_days}d")).unwrap();

    assert_eq!(days, largest_days);
    assert!(days.checked_mul(SECONDS_PER_DAY).is_some());
}

/// Zero and negative counts are refused before the unit is applied, so every
/// day count that comes back is at least one.
///
/// Callers rely on this to skip a positivity check of their own: `trust purge`
/// takes the count straight from here, and a check it repeated would be
/// unreachable rather than defensive.
#[test]
fn test_parse_relative_duration_days_rejects_a_non_positive_count_error() {
    for text in ["0d", "0m", "0y", "-1d", "-12m"] {
        let error = parse_relative_duration_days(text).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::Parse, "accepted {text}");
        assert!(
            error.to_string().contains("Duration must be positive"),
            "unexpected message for {text}: {error}"
        );
    }
}

/// The smallest span each unit can name is still a whole positive day, so no
/// accepted input rounds down to zero.
#[test]
fn test_parse_relative_duration_days_returns_at_least_one_day() {
    for text in ["1d", "1m", "1y"] {
        assert!(parse_relative_duration_days(text).unwrap() >= 1, "{text}");
    }
}
