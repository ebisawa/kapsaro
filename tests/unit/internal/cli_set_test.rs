// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests that a set write keeps its value available for every attempt.
//! Covers the retry a trust store reset runs the write with.

use super::copy_set_value;
use kapsaro_core::api::secret::SecretString;

/// A trust store reset runs the write a second time, so the value the command
/// resolved has to still produce the same secret when the retry builds its
/// entry.
#[test]
fn test_set_value_is_copied_again_for_a_retried_write() {
    let value = SecretString::new("s3cret".to_string());

    let first_attempt = copy_set_value(&value);
    let second_attempt = copy_set_value(&value);

    assert_eq!(first_attempt.expose_secret(), "s3cret");
    assert_eq!(second_attempt.expose_secret(), "s3cret");
}
