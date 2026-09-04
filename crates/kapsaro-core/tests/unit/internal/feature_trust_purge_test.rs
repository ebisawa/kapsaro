// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests the cut-off that selects stored approvals for a purge.
//! Fixes the boundary and the field each record type is reported under.

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::service_test_utils::{build_known_key, build_recipient_set};

use super::{collect_purge_candidates, purge_records};

const KID1: &str = "KJD1AAAA1111BBBB2222CCCC3333DDDD";
const KID2: &str = "KJD2AAAA1111BBBB2222CCCC3333DDDD";
const SID: &str = "6f1b6d2e-9a3a-4a0a-8c1e-0f2a3b4c5d6e";
const CUT_OFF: &str = "2026-03-29T12:40:00Z";
const OLDER: &str = "2026-03-29T12:39:59Z";

fn cut_off() -> OffsetDateTime {
    OffsetDateTime::parse(CUT_OFF, &Rfc3339).unwrap()
}

/// The cut-off is exclusive, so an approval recorded at exactly that moment is
/// kept. A run that names the moment of an approval never removes it.
#[test]
fn test_collect_purge_candidates_keeps_a_record_approved_at_the_cut_off() {
    let keys = vec![
        build_known_key(KID1, "bob", Some(CUT_OFF)),
        build_known_key(KID2, "carol", Some(OLDER)),
    ];

    let candidates = collect_purge_candidates(&keys, cut_off()).unwrap();

    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].kid, KID2);
}

/// Removal selects exactly what the listing selected, and the records that stay
/// keep their stored order.
#[test]
fn test_purge_records_removes_only_records_older_than_the_cut_off() {
    let mut keys = vec![
        build_known_key(KID1, "bob", Some(CUT_OFF)),
        build_known_key(KID2, "carol", Some(OLDER)),
    ];

    let removed = purge_records(&mut keys, cut_off()).unwrap();

    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].kid, KID2);
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].kid, KID1);
}

/// A timestamp that will not parse is reported under the field the stored
/// document names it by, so the operator can find it.
#[test]
fn test_collect_purge_candidates_names_the_known_key_field_error() {
    let keys = vec![build_known_key(KID1, "bob", Some("not-a-timestamp"))];

    let error = collect_purge_candidates(&keys, cut_off())
        .expect_err("a timestamp that will not parse must be reported");

    let message = error.format_user_message();
    assert!(message.contains("known_keys[].approved_at"), "{message}");
    assert!(message.contains("not-a-timestamp"), "{message}");
}

#[test]
fn test_collect_purge_candidates_names_the_recipient_set_field_error() {
    let records = vec![build_recipient_set(SID, &[KID1], "not-a-timestamp")];

    let error = collect_purge_candidates(&records, cut_off())
        .expect_err("a timestamp that will not parse must be reported");

    let message = error.format_user_message();
    assert!(
        message.contains("recipient_sets[].approved_at"),
        "{message}"
    );
    assert!(message.contains("not-a-timestamp"), "{message}");
}
