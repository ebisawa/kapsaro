// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Internal tests for the recovery route a trust store failure is reported with.
//! Covers which failures gain a reset offer and that none of them lose its cause.

use super::attach_trust_store_recovery;
use crate::error::{
    LOCAL_KEYSTORE_MISSING_RECOVERY, LOCAL_STATE_PATH_UNSAFE_RECOVERY,
    TRUST_SIGNER_KEY_MISSING_RECOVERY, TRUST_STORE_RESET_REQUIRED_RECOVERY,
};
use crate::{Error, ErrorKind};
use std::path::Path;

const STORE_PATH: &str = "/tmp/.kapsaro/trust/alice.json";

/// A document that will not parse is a document to reset, and it is still a
/// parse failure. An embedding application that logs malformed JSON differently
/// from a forged signature reads that from the kind, which the recovery route
/// rides alongside rather than replacing.
#[test]
fn test_unparsable_store_keeps_its_kind_and_gains_the_reset_recovery() {
    let inner = Error::build_parse_error("bad JSON");

    let error = attach_trust_store_recovery(Path::new(STORE_PATH), inner);

    assert_eq!(error.kind(), ErrorKind::Parse);
    assert_eq!(error.recovery(), Some(TRUST_STORE_RESET_REQUIRED_RECOVERY));
    assert_eq!(error.rule(), None);
    assert!(error.format_user_message().contains("alice.json"));
    assert!(error.format_user_message().contains("bad JSON"));
}

/// A signature that does not verify is a cryptographic failure, and stays one.
#[test]
fn test_invalid_signature_keeps_its_kind_and_gains_the_reset_recovery() {
    let inner = Error::build_crypto_error("signature verification failed");

    let error = attach_trust_store_recovery(Path::new(STORE_PATH), inner);

    assert_eq!(error.kind(), ErrorKind::Crypto);
    assert_eq!(error.recovery(), Some(TRUST_STORE_RESET_REQUIRED_RECOVERY));
}

/// A verification failure keeps the rule it was refused under. The rule and the
/// recovery route are separate axes, so gaining one never overwrites the other.
#[test]
fn test_verification_failure_keeps_its_rule_alongside_the_reset_recovery() {
    let inner = Error::build_verification_error("E_TRUST_OWNER_MISMATCH", "owner handle mismatch");

    let error = attach_trust_store_recovery(Path::new(STORE_PATH), inner);

    assert_eq!(error.kind(), ErrorKind::Verify);
    assert_eq!(error.rule(), Some("E_TRUST_OWNER_MISMATCH"));
    assert_eq!(error.recovery(), Some(TRUST_STORE_RESET_REQUIRED_RECOVERY));
}

/// An I/O fault never reached the document, so nothing is known about the
/// stored approvals and deleting them is not what repairs a read that failed.
#[test]
fn test_io_failure_is_never_offered_a_reset() {
    let inner = Error::build_io_error("Failed to lock directory");

    let error = attach_trust_store_recovery(Path::new(STORE_PATH), inner);

    assert_eq!(error.kind(), ErrorKind::Io);
    assert_eq!(error.recovery(), None);
    assert_eq!(error.format_user_message(), "Failed to lock directory");
}

/// An unsafe path is about what stands where local state belongs, not about the
/// content, so it keeps its own repair. Its message is left alone as well: the
/// unsafe entry can be the keystore's rather than the store's, and the failure
/// already names which path it found.
#[test]
fn test_unsafe_path_keeps_its_own_recovery_and_its_own_subject() {
    let inner = Error::build_local_state_path_unsafe_error("keys is a symlink");

    let error = attach_trust_store_recovery(Path::new(STORE_PATH), inner);

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert_eq!(error.recovery(), Some(LOCAL_STATE_PATH_UNSAFE_RECOVERY));
    assert_eq!(error.format_user_message(), "keys is a symlink");
}

/// The approvals are intact when only the signer's key is gone, and restoring
/// that one key gets them back, so the offer to discard them never appears.
#[test]
fn test_missing_signer_key_keeps_its_own_recovery() {
    let message = "Trust store signer key 'missing-kid' is unavailable";
    let inner = Error::build_verification_error(TRUST_SIGNER_KEY_MISSING_RECOVERY, message)
        .with_recovery(TRUST_SIGNER_KEY_MISSING_RECOVERY);

    let error = attach_trust_store_recovery(Path::new(STORE_PATH), inner);

    assert_eq!(error.recovery(), Some(TRUST_SIGNER_KEY_MISSING_RECOVERY));
    assert_eq!(error.format_user_message(), message);
}

/// Without the local keystore nothing was verified at all, so the store is not
/// what needs repairing and the keystore's own route is what stands.
#[test]
fn test_missing_local_keystore_keeps_its_own_recovery() {
    let message = "Local keystore '/tmp/.kapsaro/keys' is unavailable";
    let inner = Error::build_local_keystore_missing_error(message);

    let error = attach_trust_store_recovery(Path::new(STORE_PATH), inner);

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert_eq!(error.recovery(), Some(LOCAL_KEYSTORE_MISSING_RECOVERY));
    assert_eq!(error.format_user_message(), message);
}

/// Every entry point routes through this, and several of them nest, so a
/// failure that already carries the reset route is left as it stands rather
/// than being described against the store a second time.
#[test]
fn test_an_already_named_reset_is_not_described_twice() {
    let inner = Error::build_parse_error("bad JSON");
    let once = attach_trust_store_recovery(Path::new(STORE_PATH), inner);

    let twice = attach_trust_store_recovery(Path::new(STORE_PATH), once);

    assert_eq!(
        twice
            .format_user_message()
            .matches("is invalid and must be reset")
            .count(),
        1
    );
}
