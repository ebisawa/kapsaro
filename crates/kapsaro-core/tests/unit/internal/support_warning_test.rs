// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for the local state warning sink.
//! Cover deduplication, the retention cap and what one take carries away.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::thread;

use crate::support::warning::{
    record_local_state_warning, restore_local_state_warnings, LocalStateWarning,
    LocalStateWarningBatch, LocalStateWarningCapture, LocalStateWarningCode,
    LocalStateWarningGuard, MAX_LOCAL_STATE_WARNINGS,
};

fn permission_warning(reason: &str) -> LocalStateWarning {
    LocalStateWarning::new(
        LocalStateWarningCode::Permissions,
        Path::new("local-state"),
        reason.to_string(),
    )
}

fn reasons(batch: &LocalStateWarningBatch) -> Vec<&str> {
    batch
        .warnings
        .iter()
        .map(LocalStateWarning::reason)
        .collect()
}

/// A warning keeps its code and its path apart from the sentence, so a caller
/// can act on the entry without reading the wording back out.
#[test]
fn test_recorded_warning_keeps_its_code_and_path() {
    let guard = LocalStateWarningGuard::new();

    record_local_state_warning(LocalStateWarning::new(
        LocalStateWarningCode::Permissions,
        Path::new("local-state/config.toml"),
        "Insecure permissions 0644".to_string(),
    ));
    let batch = guard.take();

    assert_eq!(batch.warnings.len(), 1);
    assert_eq!(batch.warnings[0].code(), LocalStateWarningCode::Permissions);
    assert_eq!(
        batch.warnings[0].path(),
        Path::new("local-state/config.toml")
    );
    assert_eq!(batch.warnings[0].reason(), "Insecure permissions 0644");
    assert_eq!(batch.dropped, 0);
}

/// A single command inspects the same entry several times over, and the
/// operator has one thing to repair, so the finding is held once.
#[test]
fn test_repeated_warning_is_held_once() {
    let guard = LocalStateWarningGuard::new();

    for _ in 0..3 {
        record_local_state_warning(permission_warning("Insecure permissions on the config"));
    }
    record_local_state_warning(permission_warning(
        "Insecure permissions on the trust store",
    ));
    let batch = guard.take();

    assert_eq!(
        reasons(&batch),
        vec![
            "Insecure permissions on the config",
            "Insecure permissions on the trust store",
        ]
    );
}

/// Taking the warnings empties the sink, so the next command reports its own
/// findings and not the ones already shown.
#[test]
fn test_take_empties_the_sink() {
    let guard = LocalStateWarningGuard::new();

    record_local_state_warning(permission_warning("Insecure permissions on the config"));
    let first = guard.take();
    let second = guard.take();

    assert_eq!(first.warnings.len(), 1);
    assert!(second.warnings.is_empty());
    assert_eq!(second.dropped, 0);
}

/// The sink holds a bounded number of findings, so a report that fills it says
/// how many it could not carry instead of passing for the whole of them.
#[test]
fn test_warnings_past_the_cap_are_counted_rather_than_held() {
    let guard = LocalStateWarningGuard::new();

    for index in 0..MAX_LOCAL_STATE_WARNINGS + 6 {
        record_local_state_warning(permission_warning(&format!(
            "Insecure permissions on entry {index}"
        )));
    }
    let batch = guard.take();

    assert_eq!(batch.warnings.len(), MAX_LOCAL_STATE_WARNINGS);
    assert_eq!(batch.dropped, 6);
}

/// A finding the cap turned away arrives again and again during one command.
/// The count past the cap tracks distinct findings, which is what the operator
/// still has to repair.
#[test]
fn test_repeated_dropped_warning_is_counted_once() {
    let guard = LocalStateWarningGuard::new();

    for index in 0..MAX_LOCAL_STATE_WARNINGS {
        record_local_state_warning(permission_warning(&format!(
            "Insecure permissions on entry {index}"
        )));
    }
    for _ in 0..3 {
        record_local_state_warning(permission_warning("Insecure permissions on the config"));
        record_local_state_warning(permission_warning(
            "Insecure permissions on the trust store",
        ));
    }
    let batch = guard.take();

    assert_eq!(batch.warnings.len(), MAX_LOCAL_STATE_WARNINGS);
    assert_eq!(batch.dropped, 2);
}

/// The count of turned-away findings carries the same cap as the sink, so a
/// caller that never drains reads it as a floor on what is missing.
#[test]
fn test_dropped_count_stops_at_the_cap() {
    let guard = LocalStateWarningGuard::new();

    for index in 0..MAX_LOCAL_STATE_WARNINGS * 3 {
        record_local_state_warning(permission_warning(&format!(
            "Insecure permissions on entry {index}"
        )));
    }
    let batch = guard.take();

    assert_eq!(batch.warnings.len(), MAX_LOCAL_STATE_WARNINGS);
    assert_eq!(batch.dropped, MAX_LOCAL_STATE_WARNINGS);
}

/// A repeat of a held finding is never a loss, so it is not counted as one
/// even once the sink is full.
#[test]
fn test_repeat_of_a_held_warning_past_the_cap_is_not_counted() {
    let guard = LocalStateWarningGuard::new();

    for index in 0..MAX_LOCAL_STATE_WARNINGS {
        record_local_state_warning(permission_warning(&format!(
            "Insecure permissions on entry {index}"
        )));
    }
    record_local_state_warning(permission_warning("Insecure permissions on entry 0"));
    let batch = guard.take();

    assert_eq!(batch.warnings.len(), MAX_LOCAL_STATE_WARNINGS);
    assert_eq!(batch.dropped, 0);
}

/// A take restricted to one root carries away the findings recorded below it,
/// so a test asserts on the tree it staged rather than on the machine it runs on.
#[test]
fn test_take_reasons_under_carries_the_warnings_below_the_root() {
    let guard = LocalStateWarningGuard::new();

    record_local_state_warning(LocalStateWarning::new(
        LocalStateWarningCode::Permissions,
        Path::new("/a/b"),
        "Insecure permissions on the staged tree".to_string(),
    ));
    record_local_state_warning(LocalStateWarning::new(
        LocalStateWarningCode::Permissions,
        Path::new("/a"),
        "Insecure permissions on an ancestor".to_string(),
    ));

    let reasons = guard.take_reasons_under(Path::new("/a/b"));

    assert_eq!(reasons, vec!["Insecure permissions on the staged tree"]);
}

/// The sink is bound to the thread that recorded into it, so a take on one
/// thread recovers exactly what that thread itself recorded, whatever another
/// thread recorded and took around the same time.
#[test]
fn test_take_recovers_exactly_the_warnings_recorded_on_the_same_thread() {
    let guard = LocalStateWarningGuard::new();
    record_local_state_warning(permission_warning(
        "Insecure permissions on the main thread",
    ));

    let worker_reasons = thread::spawn(|| {
        let worker_guard = LocalStateWarningGuard::new();
        record_local_state_warning(permission_warning(
            "Insecure permissions on the worker thread",
        ));
        reasons(&worker_guard.take())
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()
    })
    .join()
    .unwrap();

    let main_batch = guard.take();

    assert_eq!(
        worker_reasons,
        vec!["Insecure permissions on the worker thread"]
    );
    assert_eq!(
        reasons(&main_batch),
        vec!["Insecure permissions on the main thread"]
    );
}

/// Completing a scoped operation returns only its warnings and restores the
/// caller's warnings without consuming them.
#[test]
fn test_capture_finish_returns_operation_warnings_and_restores_existing_warnings() {
    let guard = LocalStateWarningGuard::new();
    record_local_state_warning(permission_warning("Existing warning"));

    let capture = LocalStateWarningCapture::new();
    record_local_state_warning(permission_warning("Operation warning"));
    let operation_batch = capture.finish();

    assert_eq!(reasons(&operation_batch), vec!["Operation warning"]);
    assert_eq!(reasons(&guard.take()), vec!["Existing warning"]);
}

/// A service-owned warning batch can be returned to the command sink without
/// losing the lower bound for findings that did not fit in the batch.
#[test]
fn test_restore_batch_preserves_warnings_and_truncation() {
    let guard = LocalStateWarningGuard::new();
    record_local_state_warning(permission_warning("Existing warning"));

    restore_local_state_warnings(LocalStateWarningBatch {
        warnings: vec![permission_warning("Operation warning")],
        dropped: 3,
    });

    let restored = guard.take();
    assert_eq!(
        reasons(&restored),
        vec!["Existing warning", "Operation warning"]
    );
    assert_eq!(restored.dropped, 3);
}

/// Abandoning a scoped operation keeps its warnings available to the caller,
/// while preserving the sink's ordering and deduplication contract.
#[test]
fn test_capture_drop_merges_operation_warnings_into_existing_sink() {
    let guard = LocalStateWarningGuard::new();
    record_local_state_warning(permission_warning("Existing warning"));

    {
        let _capture = LocalStateWarningCapture::new();
        record_local_state_warning(permission_warning("Existing warning"));
        record_local_state_warning(permission_warning("Operation warning"));
    }

    assert_eq!(
        reasons(&guard.take()),
        vec!["Existing warning", "Operation warning"]
    );
}

/// A panic follows the same recovery path as an ordinary early return, so no
/// warning recorded before unwinding disappears with the capture guard.
#[test]
fn test_capture_panic_merges_operation_warnings_into_existing_sink() {
    let guard = LocalStateWarningGuard::new();
    record_local_state_warning(permission_warning("Existing warning"));

    let panic_result = catch_unwind(AssertUnwindSafe(|| {
        let _capture = LocalStateWarningCapture::new();
        record_local_state_warning(permission_warning("Operation warning"));
        panic!("operation failed");
    }));

    assert!(panic_result.is_err());
    assert_eq!(
        reasons(&guard.take()),
        vec!["Existing warning", "Operation warning"]
    );
}

/// Nested captures restore the immediately enclosing sink. A completed inner
/// operation is returned separately, while a dropped one rejoins its parent.
#[test]
fn test_nested_captures_restore_and_merge_with_the_immediate_parent() {
    let guard = LocalStateWarningGuard::new();
    record_local_state_warning(permission_warning("Existing warning"));

    let outer = LocalStateWarningCapture::new();
    record_local_state_warning(permission_warning("Outer warning"));
    let inner = LocalStateWarningCapture::new();
    record_local_state_warning(permission_warning("Completed inner warning"));
    let inner_batch = inner.finish();
    {
        let _inner = LocalStateWarningCapture::new();
        record_local_state_warning(permission_warning("Dropped inner warning"));
    }
    let outer_batch = outer.finish();

    assert_eq!(reasons(&inner_batch), vec!["Completed inner warning"]);
    assert_eq!(
        reasons(&outer_batch),
        vec!["Outer warning", "Dropped inner warning"]
    );
    assert_eq!(reasons(&guard.take()), vec!["Existing warning"]);
}

/// Merging an abandoned capture uses the same bounded sink as direct records,
/// including the distinct-warning count beyond the retention cap.
#[test]
fn test_capture_drop_merges_with_the_existing_sink_cap() {
    let guard = LocalStateWarningGuard::new();
    for index in 0..MAX_LOCAL_STATE_WARNINGS - 1 {
        record_local_state_warning(permission_warning(&format!("Existing {index}")));
    }

    {
        let _capture = LocalStateWarningCapture::new();
        for index in 0..4 {
            record_local_state_warning(permission_warning(&format!("Operation {index}")));
        }
    }
    let batch = guard.take();

    assert_eq!(batch.warnings.len(), MAX_LOCAL_STATE_WARNINGS);
    assert_eq!(batch.warnings.last().unwrap().reason(), "Operation 0");
    assert_eq!(batch.dropped, 3);
}
