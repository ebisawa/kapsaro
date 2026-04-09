// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for feature/disclosure module.

use secretenv::feature::disclosure::{add_to_removed_history, merge_removed_history};
use secretenv::model::common::RemovedRecipient;

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
    assert_eq!(removed.as_ref().unwrap()[0].rid, "alice@example.com");
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
            rid: "alice@example.com".to_string(),
            kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
            removed_at: "2024-01-01T00:00:00Z".to_string(),
        },
        RemovedRecipient {
            rid: "bob@example.com".to_string(),
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
        rid: "charlie@example.com".to_string(),
        kid: "01HABC1234DEFGHIJKLMNOPQRS".to_string(),
        removed_at: "2024-01-03T00:00:00Z".to_string(),
    }]);
    let source = Some(vec![RemovedRecipient {
        rid: "alice@example.com".to_string(),
        kid: "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD".to_string(),
        removed_at: "2024-01-01T00:00:00Z".to_string(),
    }]);

    merge_removed_history(&mut target, source.as_ref());

    assert_eq!(target.as_ref().unwrap().len(), 2);
}
