// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the wording of a change reported alongside a later failure.
//! Covers both `CompletedChange` branches directly, since the callers that
//! reach them (keystore and trust store saves) only exercise a few of the
//! eight call sites between them.

use std::path::Path;

use super::{format_post_change_failure, CompletedChange};

#[test]
fn test_format_post_change_failure_reports_a_write_as_written() {
    let message = format_post_change_failure(
        "Trust store",
        Path::new("/home/alice/trust/alice.json"),
        CompletedChange::Written,
        "the local trust directory became unsafe immediately after",
        "unexpected entry",
    );

    assert!(message.contains("was written"), "{message}");
    assert!(!message.contains("was removed"), "{message}");
}

#[test]
fn test_format_post_change_failure_reports_a_removal_as_removed() {
    let message = format_post_change_failure(
        "Key pair",
        Path::new("/home/alice/keys/alice/K1"),
        CompletedChange::Removed,
        "the directory became unsafe immediately after",
        "unexpected entry",
    );

    assert!(message.contains("was removed"), "{message}");
    assert!(!message.contains("was written"), "{message}");
}

/// The subject and detail travel through unaltered, so a caller's own wording
/// survives into the final message rather than being paraphrased.
#[test]
fn test_format_post_change_failure_carries_the_subject_condition_and_detail() {
    let message = format_post_change_failure(
        "Key pair",
        Path::new("/home/alice/keys/alice/K1"),
        CompletedChange::Removed,
        "the keystore directory became unsafe immediately after",
        "unexpected symlink",
    );

    assert!(message.starts_with("Key pair"), "{message}");
    assert!(
        message.contains("the keystore directory became unsafe immediately after"),
        "{message}"
    );
    assert!(message.ends_with("unexpected symlink"), "{message}");
}
