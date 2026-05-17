// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for feature/disclosure module.

use secretenv_core::cli_api::test_support::domain::common::RemovedRecipient;
use secretenv_core::cli_api::test_support::operations::disclosure::{
    add_to_removed_history, merge_removed_history,
};

#[test]
fn test_add_to_removed_history() {
    let mut removed: Option<Vec<RemovedRecipient>> = None;

    add_to_removed_history(
        &mut removed,
        "alice@example.com",
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
    )
    .unwrap();

    assert!(removed.is_some());
    assert_eq!(removed.as_ref().unwrap().len(), 1);
    assert_eq!(
        removed.as_ref().unwrap()[0].recipient_handle,
        "alice@example.com"
    );
    assert_eq!(
        removed.as_ref().unwrap()[0].kid,
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD"
    );
}

#[test]
fn test_add_to_removed_history_multiple() {
    let mut removed: Option<Vec<RemovedRecipient>> = None;

    add_to_removed_history(
        &mut removed,
        "alice@example.com",
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
    )
    .unwrap();
    add_to_removed_history(
        &mut removed,
        "bob@example.com",
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE",
    )
    .unwrap();

    assert_eq!(removed.as_ref().unwrap().len(), 2);
}

#[test]
fn test_merge_removed_history() {
    let mut target: Option<Vec<RemovedRecipient>> = None;
    let source = Some(vec![
        RemovedRecipient {
            recipient_handle: "alice@example.com".to_string(),
            kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
            removed_at: "2024-01-01T00:00:00Z".to_string(),
        },
        RemovedRecipient {
            recipient_handle: "bob@example.com".to_string(),
            kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE".to_string(),
            removed_at: "2024-01-02T00:00:00Z".to_string(),
        },
    ]);

    merge_removed_history(&mut target, source.as_ref());

    assert!(target.is_some());
    assert_eq!(target.as_ref().unwrap().len(), 2);
}

#[test]
fn test_merge_removed_history_into_existing() {
    let mut target = Some(vec![RemovedRecipient {
        recipient_handle: "charlie@example.com".to_string(),
        kid: "01HABC1234DEFGHIJKLMNOPQRS".to_string(),
        removed_at: "2024-01-03T00:00:00Z".to_string(),
    }]);
    let source = Some(vec![RemovedRecipient {
        recipient_handle: "alice@example.com".to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
        removed_at: "2024-01-01T00:00:00Z".to_string(),
    }]);

    merge_removed_history(&mut target, source.as_ref());

    assert_eq!(target.as_ref().unwrap().len(), 2);
}

#[test]
fn test_add_to_removed_history_same_kid_updates_existing_record() {
    let original_removed_at = "2024-01-01T00:00:00Z";
    let mut removed = Some(vec![RemovedRecipient {
        recipient_handle: "alice@example.com".to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
        removed_at: original_removed_at.to_string(),
    }]);

    add_to_removed_history(
        &mut removed,
        "alice@example.com",
        "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD",
    )
    .unwrap();

    let removed = removed.unwrap();
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].recipient_handle, "alice@example.com");
    assert_ne!(removed[0].removed_at, original_removed_at);
}

#[test]
fn test_merge_removed_history_deduplicates_by_kid() {
    let retained = RemovedRecipient {
        recipient_handle: "alice@example.com".to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
        removed_at: "2024-01-03T00:00:00Z".to_string(),
    };
    let mut target = Some(vec![retained.clone()]);
    let source = Some(vec![
        RemovedRecipient {
            recipient_handle: "alice@example.com".to_string(),
            kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
            removed_at: "2024-01-01T00:00:00Z".to_string(),
        },
        RemovedRecipient {
            recipient_handle: "bob@example.com".to_string(),
            kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GE".to_string(),
            removed_at: "2024-01-02T00:00:00Z".to_string(),
        },
    ]);

    merge_removed_history(&mut target, source.as_ref());

    let target = target.unwrap();
    assert_eq!(target.len(), 2);
    let alice = target
        .iter()
        .find(|recipient| recipient.kid == retained.kid)
        .unwrap();
    assert_eq!(alice.removed_at, retained.removed_at);
}
