// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests reset recovery control flow for review-bound trust mutations.
//! Ensures recovery does not reapply a decision to unreviewed replacement state.

use std::cell::Cell;
use std::path::Path;

use super::{
    run_with_trust_store_reset_retry, run_with_trust_store_reset_without_retry,
    trust_store_reset_prompt, TrustStoreResetOutcome,
};
use kapsaro_core::cli_api::app::trust::recovery::{TrustStoreResetCause, TrustStoreResetLoss};
use kapsaro_core::cli_api::test_support::helpers::recovery;
use kapsaro_core::{Error, Result};

fn build_reset_required_error() -> Error {
    recovery::build_unparsable_trust_store_error("Local trust store is invalid")
}

fn build_local_keystore_missing_error() -> Error {
    recovery::build_local_keystore_missing_error("Local keystore is unavailable")
}

fn build_missing_signer_key_error() -> Error {
    recovery::build_missing_trust_signer_key_error("Trust store signer key is unavailable")
}

/// Content that would not load names no count, so the operator is asked the
/// plain question rather than told a figure nothing stands behind.
#[test]
fn test_invalid_document_reset_prompt_identifies_invalid_store() {
    let prompt = trust_store_reset_prompt(
        Path::new("/tmp/.kapsaro/trust/alice.json"),
        TrustStoreResetCause::InvalidDocument,
        None,
        None,
    );

    assert_eq!(
        prompt,
        "Delete invalid local trust store '/tmp/.kapsaro/trust/alice.json' and continue with an empty trust cache?"
    );
}

#[test]
fn test_missing_signer_key_reset_prompt_identifies_missing_key() {
    let prompt = trust_store_reset_prompt(
        Path::new("/tmp/.kapsaro/trust/alice.json"),
        TrustStoreResetCause::MissingSignerKey,
        None,
        None,
    );

    assert_eq!(
        prompt,
        "Delete local trust store '/tmp/.kapsaro/trust/alice.json' because its signer key is unavailable and continue with an empty trust cache?"
    );
}

/// A store whose signer key is merely missing keeps its approvals intact, so
/// the prompt says how many of them the deletion would take away.
#[test]
fn test_reset_prompt_states_how_many_approvals_the_deletion_discards() {
    let prompt = trust_store_reset_prompt(
        Path::new("/tmp/.kapsaro/trust/alice.json"),
        TrustStoreResetCause::MissingSignerKey,
        Some(TrustStoreResetLoss {
            known_keys: 3,
            recipient_sets: 1,
        }),
        Some("Put the key back to keep them."),
    );

    assert_eq!(
        prompt,
        "This discards 3 approved keys and 1 approved recipient set. Put the key back to keep them. Delete local trust store '/tmp/.kapsaro/trust/alice.json' because its signer key is unavailable and continue with an empty trust cache?"
    );
}

#[test]
fn test_reset_prompt_states_an_empty_store_as_zero_approvals() {
    let prompt = trust_store_reset_prompt(
        Path::new("/tmp/.kapsaro/trust/alice.json"),
        TrustStoreResetCause::InvalidDocument,
        Some(TrustStoreResetLoss {
            known_keys: 0,
            recipient_sets: 0,
        }),
        None,
    );

    assert!(
        prompt.starts_with("This discards 0 approved keys and 0 approved recipient sets."),
        "{prompt}"
    );
}

#[test]
fn test_reset_recovery_reports_an_empty_result_for_a_review_bound_operation() {
    let run_calls = Cell::new(0);
    let recovery_calls = Cell::new(0);

    let outcome = run_with_trust_store_reset_without_retry(
        || -> Result<()> {
            run_calls.set(run_calls.get() + 1);
            Err(build_reset_required_error())
        },
        |_| {
            recovery_calls.set(recovery_calls.get() + 1);
            Ok(())
        },
    )
    .unwrap();

    assert!(matches!(outcome, TrustStoreResetOutcome::ResetToEmpty));
    assert_eq!(run_calls.get(), 1);
    assert_eq!(recovery_calls.get(), 1);
}

#[test]
fn test_missing_signer_key_starts_reset_recovery() {
    let recovery_calls = Cell::new(0);

    let outcome = run_with_trust_store_reset_without_retry(
        || -> Result<()> { Err(build_missing_signer_key_error()) },
        |_| {
            recovery_calls.set(recovery_calls.get() + 1);
            Ok(())
        },
    )
    .unwrap();

    assert!(matches!(outcome, TrustStoreResetOutcome::ResetToEmpty));
    assert_eq!(recovery_calls.get(), 1);
}

/// The retry flow exists so the operation runs once more on the empty cache the
/// reset left behind, which is the state the operator agreed to continue from.
#[test]
fn test_retry_recovery_runs_the_operation_again_after_the_reset() {
    let run_calls = Cell::new(0);
    let recovery_calls = Cell::new(0);

    let value = run_with_trust_store_reset_retry(
        || {
            run_calls.set(run_calls.get() + 1);
            if run_calls.get() == 1 {
                Err(build_reset_required_error())
            } else {
                Ok("second run")
            }
        },
        |_| {
            recovery_calls.set(recovery_calls.get() + 1);
            Ok(())
        },
    )
    .unwrap();

    assert_eq!(value, "second run");
    assert_eq!(run_calls.get(), 2);
    assert_eq!(recovery_calls.get(), 1);
}

/// One reset is all the operator agreed to. A second failure of the same kind
/// means the empty cache did not help, so it is reported instead of prompting
/// for another deletion.
#[test]
fn test_retry_recovery_reports_a_second_failure_without_resetting_again() {
    let run_calls = Cell::new(0);
    let recovery_calls = Cell::new(0);

    let error = run_with_trust_store_reset_retry(
        || -> Result<()> {
            run_calls.set(run_calls.get() + 1);
            Err(build_reset_required_error())
        },
        |_| {
            recovery_calls.set(recovery_calls.get() + 1);
            Ok(())
        },
    )
    .unwrap_err();

    assert_eq!(error.recovery(), Some("E_TRUST_STORE_RESET_REQUIRED"));
    assert_eq!(run_calls.get(), 2);
    assert_eq!(recovery_calls.get(), 1);
}

#[test]
fn test_retry_recovery_returns_missing_local_keystore_error_to_caller() {
    let run_calls = Cell::new(0);
    let recovery_calls = Cell::new(0);

    let error = run_with_trust_store_reset_retry(
        || -> Result<()> {
            run_calls.set(run_calls.get() + 1);
            Err(build_local_keystore_missing_error())
        },
        |_| {
            recovery_calls.set(recovery_calls.get() + 1);
            Ok(())
        },
    )
    .unwrap_err();

    assert_eq!(error.recovery(), Some("E_LOCAL_KEYSTORE_MISSING"));
    assert_eq!(run_calls.get(), 1);
    assert_eq!(recovery_calls.get(), 0);
}

#[test]
fn test_without_retry_recovery_returns_missing_local_keystore_error_to_caller() {
    let run_calls = Cell::new(0);
    let recovery_calls = Cell::new(0);

    let error = match run_with_trust_store_reset_without_retry(
        || -> Result<()> {
            run_calls.set(run_calls.get() + 1);
            Err(build_local_keystore_missing_error())
        },
        |_| {
            recovery_calls.set(recovery_calls.get() + 1);
            Ok(())
        },
    ) {
        Err(error) => error,
        Ok(_) => panic!("missing local keystore must not start reset recovery"),
    };

    assert_eq!(error.recovery(), Some("E_LOCAL_KEYSTORE_MISSING"));
    assert_eq!(run_calls.get(), 1);
    assert_eq!(recovery_calls.get(), 0);
}
