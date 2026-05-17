// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use secretenv_core::cli_api::test_support::domain::common::WrapItem;
use secretenv_core::cli_api::test_support::domain::trust_store::{
    RecipientSetApprovalVia, RecipientSetRecord,
};
use secretenv_core::cli_api::test_support::operations::trust::recipient_sets::{
    compute_recipient_set_hash, judge_recipient_set, ArtifactRecipientSet, RecipientSetJudgment,
};
use uuid::Uuid;

#[test]
fn test_from_wrap_items_captures_sorted_recipient_handle_hints() {
    let sid = Uuid::nil();
    let set = ArtifactRecipientSet::from_wrap_items(
        sid,
        &[
            wrap_item("bob@example.com", "KBD2AAAA1111BBBB2222CCCC3333DDDD"),
            wrap_item("alice@example.com", "KAD1AAAA1111BBBB2222CCCC3333DDDD"),
        ],
    )
    .unwrap();

    let hints = set.recipient_handle_hints();
    assert_eq!(hints.len(), 2);
    assert_eq!(hints[0].kid, "KAD1AAAA1111BBBB2222CCCC3333DDDD");
    assert_eq!(hints[0].recipient_handle, "alice@example.com");
    assert_eq!(hints[1].kid, "KBD2AAAA1111BBBB2222CCCC3333DDDD");
    assert_eq!(hints[1].recipient_handle, "bob@example.com");
}

#[test]
fn test_recipient_handle_hints_do_not_affect_hash_or_judgment() {
    let sid = Uuid::nil();
    let current = ArtifactRecipientSet::from_wrap_items(
        sid,
        &[wrap_item(
            "alice-new@example.com",
            "KAD1AAAA1111BBBB2222CCCC3333DDDD",
        )],
    )
    .unwrap();
    let approved = recipient_set_record(
        sid,
        &["KAD1AAAA1111BBBB2222CCCC3333DDDD"],
        Some("alice-old@example.com"),
    );

    assert_eq!(
        current.recipient_set_hash(),
        compute_recipient_set_hash(current.recipient_kids()).unwrap()
    );
    assert_eq!(
        judge_recipient_set(&[approved], &current),
        RecipientSetJudgment::Accepted
    );
}

#[test]
fn test_into_record_persists_recipient_handle_hints() {
    let set = ArtifactRecipientSet::from_wrap_items(
        Uuid::nil(),
        &[wrap_item(
            "alice@example.com",
            "KAD1AAAA1111BBBB2222CCCC3333DDDD",
        )],
    )
    .unwrap();

    let record = set.into_record("2026-05-01T00:00:00Z".to_string());

    let hints = record.recipient_handle_hints.unwrap();
    assert_eq!(hints[0].kid, "KAD1AAAA1111BBBB2222CCCC3333DDDD");
    assert_eq!(hints[0].recipient_handle, "alice@example.com");
}

fn recipient_set_record(
    sid: Uuid,
    kids: &[&str],
    hint_member_handle: Option<&str>,
) -> RecipientSetRecord {
    let recipient_kids = kids
        .iter()
        .map(|kid| (*kid).to_string())
        .collect::<Vec<_>>();
    let recipient_handle_hints = hint_member_handle.map(|recipient_handle| {
        recipient_kids
            .iter()
            .map(|kid| {
                secretenv_core::cli_api::test_support::domain::trust_store::RecipientHandleHint {
                    kid: kid.clone(),
                    recipient_handle: recipient_handle.to_string(),
                }
            })
            .collect()
    });
    RecipientSetRecord {
        sid: sid.to_string(),
        recipient_set_hash: compute_recipient_set_hash(&recipient_kids).unwrap(),
        recipient_kids,
        approved_at: "2026-05-01T00:00:00Z".to_string(),
        approved_via: RecipientSetApprovalVia::ManualReview,
        recipient_handle_hints,
    }
}

fn wrap_item(recipient_handle: &str, kid: &str) -> WrapItem {
    WrapItem {
        recipient_handle: recipient_handle.to_string(),
        kid: kid.to_string(),
        alg: "hpke-32-1-3".to_string(),
        enc: "enc".to_string(),
        ct: "ct".to_string(),
    }
}
