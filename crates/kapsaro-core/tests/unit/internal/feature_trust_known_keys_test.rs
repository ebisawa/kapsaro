// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for known_keys operations

use crate::feature::trust::known_keys::{
    add_known_key, enforce_kid_integrity, find_known_key, judge_known_key, purge_known_keys,
    remove_known_key, KnownKeyJudgment,
};
use crate::service_test_utils::build_known_key;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

fn parse_timestamp(ts: &str) -> OffsetDateTime {
    OffsetDateTime::parse(ts, &Rfc3339).unwrap()
}

#[test]
fn test_add_known_key_adds_new_entry() {
    let mut keys = Vec::new();
    let added = add_known_key(
        &mut keys,
        build_known_key("KJD1AAAA1111BBBB2222CCCC3333DDDD", "bob", None),
    )
    .unwrap();
    assert!(added);
    assert_eq!(keys.len(), 1);
}

#[test]
fn test_add_known_key_same_kid_same_member_noop() {
    let mut keys = vec![build_known_key(
        "KJD1AAAA1111BBBB2222CCCC3333DDDD",
        "bob",
        None,
    )];
    let added = add_known_key(
        &mut keys,
        build_known_key("KJD1AAAA1111BBBB2222CCCC3333DDDD", "bob", None),
    )
    .unwrap();
    assert!(!added);
    assert_eq!(keys.len(), 1);
}

#[test]
fn test_judge_known_key_reports_existing_entry() {
    let keys = vec![build_known_key(
        "KJD1AAAA1111BBBB2222CCCC3333DDDD",
        "bob",
        None,
    )];

    let result = judge_known_key(&keys, "KJD1AAAA1111BBBB2222CCCC3333DDDD", "bob").unwrap();

    assert_eq!(result, KnownKeyJudgment::Existing);
}

#[test]
fn test_judge_known_key_reports_new_entry() {
    let keys = vec![build_known_key(
        "KJD1AAAA1111BBBB2222CCCC3333DDDD",
        "bob",
        None,
    )];

    let result = judge_known_key(&keys, "KJD2AAAA1111BBBB2222CCCC3333DDDD", "charlie").unwrap();

    assert_eq!(result, KnownKeyJudgment::New);
}

#[test]
fn test_add_known_key_same_kid_different_member_fails() {
    let mut keys = vec![build_known_key(
        "KJD1AAAA1111BBBB2222CCCC3333DDDD",
        "bob",
        None,
    )];
    let result = add_known_key(
        &mut keys,
        build_known_key("KJD1AAAA1111BBBB2222CCCC3333DDDD", "charlie", None),
    );
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("INTEGRITY_ANOMALY") || msg.contains("integrity"));
}

#[test]
fn test_remove_known_key_removes_existing_entry() {
    let mut keys = vec![build_known_key(
        "KJD1AAAA1111BBBB2222CCCC3333DDDD",
        "bob",
        None,
    )];
    let removed = remove_known_key(&mut keys, "KJD1AAAA1111BBBB2222CCCC3333DDDD").unwrap();
    assert_eq!(removed.subject_handle, "bob");
    assert!(keys.is_empty());
}

#[test]
fn test_remove_known_key_not_found_fails() {
    let mut keys = Vec::new();
    let result = remove_known_key(&mut keys, "ZZZZ0000111122223333444455556666");
    assert!(result.is_err());
}

#[test]
fn test_find_known_key_found() {
    let keys = vec![build_known_key(
        "KJD1AAAA1111BBBB2222CCCC3333DDDD",
        "bob",
        None,
    )];
    assert!(find_known_key(&keys, "KJD1AAAA1111BBBB2222CCCC3333DDDD").is_some());
}

#[test]
fn test_find_known_key_not_found() {
    let keys = vec![build_known_key(
        "KJD1AAAA1111BBBB2222CCCC3333DDDD",
        "bob",
        None,
    )];
    assert!(find_known_key(&keys, "ZZZZ0000111122223333444455556666").is_none());
}

#[test]
fn test_purge_known_keys_removes_old_entries() {
    let mut keys = vec![
        build_known_key("KJD1AAAA1111BBBB2222CCCC3333DDDD", "bob", None),
        {
            let mut k = build_known_key("KJD2AAAA1111BBBB2222CCCC3333DDDD", "charlie", None);
            k.approved_at = "2026-06-01T00:00:00Z".to_string();
            k
        },
    ];

    let removed = purge_known_keys(&mut keys, parse_timestamp("2026-04-01T00:00:00Z")).unwrap();
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].subject_handle, "bob");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].subject_handle, "charlie");
}

#[test]
fn test_purge_known_keys_fractional_seconds() {
    let mut keys = vec![
        build_known_key("KJD1AAAA1111BBBB2222CCCC3333DDDD", "bob", None),
        {
            let mut key = build_known_key("KJD2AAAA1111BBBB2222CCCC3333DDDD", "charlie", None);
            key.approved_at = "2026-01-01T00:00:00.1Z".to_string();
            key
        },
        {
            let mut key = build_known_key("KJD3AAAA1111BBBB2222CCCC3333DDDD", "dave", None);
            key.approved_at = "2026-06-01T00:00:00Z".to_string();
            key
        },
    ];

    keys[0].approved_at = "2026-01-01T00:00:00Z".to_string();

    let removed = purge_known_keys(&mut keys, parse_timestamp("2026-01-01T00:00:01Z")).unwrap();

    assert_eq!(removed.len(), 2);
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].kid, "KJD3AAAA1111BBBB2222CCCC3333DDDD");
}

#[test]
fn test_purge_known_keys_parse_failure_error() {
    let mut keys = vec![build_known_key(
        "KJD1AAAA1111BBBB2222CCCC3333DDDD",
        "bob",
        None,
    )];
    keys[0].approved_at = "invalid".to_string();

    let result = purge_known_keys(&mut keys, parse_timestamp("2026-04-01T00:00:00Z"));

    assert!(result.is_err());
}

#[test]
fn test_validate_kid_integrity_accepts_same_member() {
    let keys = vec![build_known_key(
        "KJD1AAAA1111BBBB2222CCCC3333DDDD",
        "bob",
        None,
    )];
    enforce_kid_integrity(&keys, "KJD1AAAA1111BBBB2222CCCC3333DDDD", "bob").unwrap();
}

#[test]
fn test_validate_kid_integrity_accepts_new_kid() {
    let keys = vec![build_known_key(
        "KJD1AAAA1111BBBB2222CCCC3333DDDD",
        "bob",
        None,
    )];
    enforce_kid_integrity(&keys, "KJD2AAAA1111BBBB2222CCCC3333DDDD", "charlie").unwrap();
}

#[test]
fn test_validate_kid_integrity_anomaly() {
    let keys = vec![build_known_key(
        "KJD1AAAA1111BBBB2222CCCC3333DDDD",
        "bob",
        None,
    )];
    let result = enforce_kid_integrity(&keys, "KJD1AAAA1111BBBB2222CCCC3333DDDD", "charlie");
    assert!(result.is_err());
}
