// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use secretenv::model::common::{WrapAlgorithm, WrapItem, WrapSet};
use secretenv::model::identifiers::hpke;

const ALICE: &str = "alice@example.com";
const BOB: &str = "bob@example.com";
const ALICE_KID: &str = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";
const BOB_KID: &str = "9K4W2H7R1M5VX8DPT3QNC6JY0F1BRG4D";
const ENC_32: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const CT_48: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn wrap_item(recipient_handle: &str, kid: &str) -> WrapItem {
    WrapItem {
        recipient_handle: recipient_handle.to_string(),
        kid: kid.to_string(),
        alg: hpke::ALG_HPKE_32_1_3.to_string(),
        enc: ENC_32.to_string(),
        ct: CT_48.to_string(),
    }
}

#[test]
fn test_wrap_set_parse_validates_domain_fields() {
    let wrap_set = WrapSet::parse(&[wrap_item(ALICE, ALICE_KID)], "Document").unwrap();
    let item = wrap_set.find_by_kid_for_member(ALICE_KID, ALICE).unwrap();

    assert_eq!(item.recipient_handle().as_str(), ALICE);
    assert_eq!(item.kid().as_str(), ALICE_KID);
    assert_eq!(item.alg(), WrapAlgorithm::Hpke32_1_3);
    assert_eq!(item.alg().as_str(), hpke::ALG_HPKE_32_1_3);
    assert_eq!(item.enc().as_bytes().len(), 32);
    assert_eq!(item.ciphertext().as_bytes().len(), 48);
}

#[test]
fn test_wrap_set_parse_rejects_invalid_member_handle() {
    let result = WrapSet::parse(&[wrap_item("-alice", ALICE_KID)], "Document");

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("member_handle"));
}

#[test]
fn test_wrap_set_parse_rejects_invalid_kid() {
    let result = WrapSet::parse(&[wrap_item(ALICE, "not-a-kid")], "Document");

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("kid"));
}

#[test]
fn test_wrap_set_parse_rejects_unsupported_algorithm() {
    let mut item = wrap_item(ALICE, ALICE_KID);
    item.alg = "unsupported-alg-99".to_string();

    let result = WrapSet::parse(&[item], "Document");

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Unsupported HPKE algorithm"));
}

#[test]
fn test_wrap_set_parse_rejects_invalid_enc_length() {
    let mut item = wrap_item(ALICE, ALICE_KID);
    item.enc = "AAAA".to_string();

    let result = WrapSet::parse(&[item], "Document");

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Invalid enc length"));
}

#[test]
fn test_wrap_set_parse_rejects_invalid_ct_length() {
    let mut item = wrap_item(ALICE, ALICE_KID);
    item.ct = "AAAA".to_string();

    let result = WrapSet::parse(&[item], "Document");

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Invalid ct length"));
}

#[test]
fn test_wrap_set_parse_rejects_duplicate_recipient_handle() {
    let result = WrapSet::parse(
        &[wrap_item(ALICE, ALICE_KID), wrap_item(ALICE, BOB_KID)],
        "Document",
    );

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("E_DUPLICATE_RECIPIENT_HANDLE"));
}

#[test]
fn test_wrap_set_find_by_kid_for_member_reports_missing_kid() {
    let wrap_set = WrapSet::parse(&[wrap_item(ALICE, ALICE_KID)], "Document").unwrap();

    let result = wrap_set.find_by_kid_for_member(BOB_KID, ALICE);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("No wrap found"));
}

#[test]
fn test_wrap_set_find_by_kid_for_member_rejects_recipient_mismatch() {
    let wrap_set = WrapSet::parse(&[wrap_item(ALICE, ALICE_KID)], "Document").unwrap();

    let result = wrap_set.find_by_kid_for_member(ALICE_KID, BOB);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("does not match member_handle"));
}

#[test]
fn test_wrap_set_self_wrap_kids_preserves_order_and_dedupes() {
    let wrap_set = WrapSet::parse(
        &[wrap_item(ALICE, ALICE_KID), wrap_item(BOB, BOB_KID)],
        "Document",
    )
    .unwrap();

    let kids = wrap_set.self_wrap_kids(ALICE);

    assert_eq!(kids.len(), 1);
    assert_eq!(kids[0].as_str(), ALICE_KID);
}
