// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for known_keys operations

use secretenv::feature::trust::known_keys::{
    add_known_key, find_known_key, judge_known_key, purge_known_keys, remove_known_key,
    validate_kid_integrity, KnownKeyJudgment,
};
use secretenv::model::trust_store::{KnownKey, KnownKeyApprovalVia};
use std::collections::BTreeMap;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

fn build_known_key(kid: &str, member_id: &str) -> KnownKey {
    KnownKey {
        kid: kid.to_string(),
        member_id: member_id.to_string(),
        approved_at: "2026-03-29T12:40:00Z".to_string(),
        approved_via: KnownKeyApprovalVia::ManualReview,
        evidence: None,
        extra: BTreeMap::new(),
    }
}

fn parse_timestamp(ts: &str) -> OffsetDateTime {
    OffsetDateTime::parse(ts, &Rfc3339).unwrap()
}

#[test]
fn test_add_known_key_adds_new_entry() {
    let mut keys = Vec::new();
    let added = add_known_key(
        &mut keys,
        build_known_key("KJD1AAAA1111BBBB2222CCCC3333DDDD", "bob"),
    )
    .unwrap();
    assert!(added);
    assert_eq!(keys.len(), 1);
}

#[test]
fn test_add_known_key_same_kid_same_member_noop() {
    let mut keys = vec![build_known_key("KJD1AAAA1111BBBB2222CCCC3333DDDD", "bob")];
    let added = add_known_key(
        &mut keys,
        build_known_key("KJD1AAAA1111BBBB2222CCCC3333DDDD", "bob"),
    )
    .unwrap();
    assert!(!added);
    assert_eq!(keys.len(), 1);
}

#[test]
fn test_judge_known_key_reports_existing_entry() {
    let keys = vec![build_known_key("KJD1AAAA1111BBBB2222CCCC3333DDDD", "bob")];

    let result = judge_known_key(&keys, "KJD1AAAA1111BBBB2222CCCC3333DDDD", "bob").unwrap();

    assert_eq!(result, KnownKeyJudgment::Existing);
}

#[test]
fn test_judge_known_key_reports_new_entry() {
    let keys = vec![build_known_key("KJD1AAAA1111BBBB2222CCCC3333DDDD", "bob")];

    let result = judge_known_key(&keys, "KJD2AAAA1111BBBB2222CCCC3333DDDD", "charlie").unwrap();

    assert_eq!(result, KnownKeyJudgment::New);
}

#[test]
fn test_add_known_key_reports_new_then_existing_duplicate() {
    let mut keys = Vec::new();
    let key = build_known_key("KJD9AAAA1111BBBB2222CCCC3333DDDD", "bob");

    let first = add_known_key(&mut keys, key.clone()).unwrap();
    let second = add_known_key(&mut keys, key).unwrap();

    assert!(first);
    assert!(!second);
    assert_eq!(keys.len(), 1);
}

#[test]
fn test_add_known_key_same_kid_different_member_fails() {
    let mut keys = vec![build_known_key("KJD1AAAA1111BBBB2222CCCC3333DDDD", "bob")];
    let result = add_known_key(
        &mut keys,
        build_known_key("KJD1AAAA1111BBBB2222CCCC3333DDDD", "charlie"),
    );
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("INTEGRITY_ANOMALY") || msg.contains("integrity"));
}

#[test]
fn test_remove_known_key_removes_existing_entry() {
    let mut keys = vec![build_known_key("KJD1AAAA1111BBBB2222CCCC3333DDDD", "bob")];
    let removed = remove_known_key(&mut keys, "KJD1AAAA1111BBBB2222CCCC3333DDDD").unwrap();
    assert_eq!(removed.member_id, "bob");
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
    let keys = vec![build_known_key("KJD1AAAA1111BBBB2222CCCC3333DDDD", "bob")];
    assert!(find_known_key(&keys, "KJD1AAAA1111BBBB2222CCCC3333DDDD").is_some());
}

#[test]
fn test_find_known_key_not_found() {
    let keys = vec![build_known_key("KJD1AAAA1111BBBB2222CCCC3333DDDD", "bob")];
    assert!(find_known_key(&keys, "ZZZZ0000111122223333444455556666").is_none());
}

#[test]
fn test_purge_known_keys_removes_old_entries() {
    let mut keys = vec![
        build_known_key("KJD1AAAA1111BBBB2222CCCC3333DDDD", "bob"),
        {
            let mut k = build_known_key("KJD2AAAA1111BBBB2222CCCC3333DDDD", "charlie");
            k.approved_at = "2026-06-01T00:00:00Z".to_string();
            k
        },
    ];

    let removed = purge_known_keys(&mut keys, parse_timestamp("2026-04-01T00:00:00Z")).unwrap();
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].member_id, "bob");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].member_id, "charlie");
}

#[test]
fn test_purge_known_keys_fractional_seconds() {
    let mut keys = vec![
        build_known_key("KJD1AAAA1111BBBB2222CCCC3333DDDD", "bob"),
        {
            let mut key = build_known_key("KJD2AAAA1111BBBB2222CCCC3333DDDD", "charlie");
            key.approved_at = "2026-01-01T00:00:00.1Z".to_string();
            key
        },
        {
            let mut key = build_known_key("KJD3AAAA1111BBBB2222CCCC3333DDDD", "dave");
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
    let mut keys = vec![build_known_key("KJD1AAAA1111BBBB2222CCCC3333DDDD", "bob")];
    keys[0].approved_at = "invalid".to_string();

    let result = purge_known_keys(&mut keys, parse_timestamp("2026-04-01T00:00:00Z"));

    assert!(result.is_err());
}

#[test]
fn test_validate_kid_integrity_accepts_same_member() {
    let keys = vec![build_known_key("KJD1AAAA1111BBBB2222CCCC3333DDDD", "bob")];
    validate_kid_integrity(&keys, "KJD1AAAA1111BBBB2222CCCC3333DDDD", "bob").unwrap();
}

#[test]
fn test_validate_kid_integrity_accepts_new_kid() {
    let keys = vec![build_known_key("KJD1AAAA1111BBBB2222CCCC3333DDDD", "bob")];
    validate_kid_integrity(&keys, "KJD2AAAA1111BBBB2222CCCC3333DDDD", "charlie").unwrap();
}

#[test]
fn test_validate_kid_integrity_anomaly() {
    let keys = vec![build_known_key("KJD1AAAA1111BBBB2222CCCC3333DDDD", "bob")];
    let result = validate_kid_integrity(&keys, "KJD1AAAA1111BBBB2222CCCC3333DDDD", "charlie");
    assert!(result.is_err());
}
