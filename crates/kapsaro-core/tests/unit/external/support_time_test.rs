// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for support/time module
//!
//! Tests for time-related helpers.

use kapsaro_core::cli_api::test_support::helpers::time::{
    format_timestamp_rfc3339, generate_current_timestamp,
};
use time::OffsetDateTime;

#[test]
fn test_format_timestamp_rfc3339() {
    let dt = OffsetDateTime::from_unix_timestamp(1609459200).unwrap(); // 2021-01-01T00:00:00Z
    let formatted = format_timestamp_rfc3339(dt).unwrap();

    assert!(formatted.contains("2021-01-01"));
    assert!(formatted.contains("00:00:00"));
}

#[test]
fn test_current_timestamp() {
    let timestamp = generate_current_timestamp().unwrap();

    // Verify it's a valid RFC 3339 timestamp
    assert!(timestamp.contains("T"));
    assert!(timestamp.contains("Z") || timestamp.contains("+") || timestamp.contains("-"));
}

#[test]
fn test_format_timestamp_rfc3339_no_subseconds() {
    let dt = OffsetDateTime::from_unix_timestamp(1609459200).unwrap();
    let formatted = format_timestamp_rfc3339(dt).unwrap();

    // Should not contain subseconds
    assert!(!formatted.contains("."));
}
