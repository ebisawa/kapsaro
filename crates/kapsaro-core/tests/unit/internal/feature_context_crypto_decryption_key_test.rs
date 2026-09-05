// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests how a decryption that found no usable local key reports what was missing.
//! Separates an artifact that wraps to nobody local from a key the keystore lost.

use super::{
    build_missing_decryption_key_error, judge_missing_decryption_key, MissingDecryptionKey,
};
use crate::model::identity::Kid;

const MEMBER: &str = "alice@example.com";
const WRAPPED_KID: &str = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";
const OTHER_KID: &str = "9K4W2H7R1M5VX8DPT3QNC6JY0F1BRG4D";

fn kid(value: &str) -> Kid {
    Kid::try_from(value).expect("canonical test kid")
}

/// The rotation shape: the artifact still wraps to the retired key, and the
/// keystore no longer holds it. Naming the wrap as missing would send the
/// operator to recipients that are intact.
#[test]
fn test_wrap_without_a_local_key_is_reported_as_the_missing_key() {
    let wrapped = kid(WRAPPED_KID);

    let missing = judge_missing_decryption_key(Some(&wrapped), Some(&wrapped));
    let error = build_missing_decryption_key_error(MEMBER, None, Some(&wrapped), missing);

    assert_eq!(missing, MissingDecryptionKey::LocalKey);
    let message = error.format_user_message().to_string();
    assert!(
        message.contains("Wrap found for kid") && message.contains("no local key"),
        "got: {message}"
    );
    assert!(message.contains(MEMBER), "got: {message}");
}

/// An artifact that wraps to nobody this member holds is the other condition,
/// and it keeps its own wording.
#[test]
fn test_absent_wrap_is_reported_as_a_missing_wrap() {
    let missing = judge_missing_decryption_key(None, None);
    let error = build_missing_decryption_key_error(MEMBER, None, None, missing);

    assert_eq!(missing, MissingDecryptionKey::Wrap);
    assert!(
        error
            .format_user_message()
            .contains("No wrap found for any local kid"),
        "got: {}",
        error.format_user_message()
    );
}

/// An explicit selection that names a key the artifact never wrapped to is a
/// missing wrap whatever the keystore holds, and it names the key that was asked
/// for.
#[test]
fn test_explicit_kid_the_artifact_does_not_wrap_to_is_reported_as_a_missing_wrap() {
    let wrapped = kid(WRAPPED_KID);
    let explicit = kid(OTHER_KID);

    let missing = judge_missing_decryption_key(Some(&wrapped), Some(&explicit));
    let error =
        build_missing_decryption_key_error(MEMBER, Some(&explicit), Some(&explicit), missing);

    assert_eq!(missing, MissingDecryptionKey::Wrap);
    let message = error.format_user_message().to_string();
    assert!(message.contains("No wrap found for kid"), "got: {message}");
    assert!(!message.contains(WRAPPED_KID), "got: {message}");
}

/// The two conditions must not read the same way: a report that cannot be told
/// apart is what sends the operator to the wrong repair.
#[test]
fn test_missing_wrap_and_missing_local_key_are_reported_differently() {
    let wrapped = kid(WRAPPED_KID);

    let missing_local_key = build_missing_decryption_key_error(
        MEMBER,
        None,
        Some(&wrapped),
        MissingDecryptionKey::LocalKey,
    );
    let missing_wrap =
        build_missing_decryption_key_error(MEMBER, None, None, MissingDecryptionKey::Wrap);

    assert_ne!(
        missing_local_key.format_user_message(),
        missing_wrap.format_user_message()
    );
}
