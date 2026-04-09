// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for internal identity newtypes.

use secretenv::model::identity::{Kid, MemberId};

#[test]
fn test_member_id_try_from_valid() {
    let member_id = MemberId::try_from("alice@example.com").unwrap();
    assert_eq!(member_id.as_str(), "alice@example.com");
}

#[test]
fn test_member_id_try_from_invalid_error() {
    let error = MemberId::try_from("@example.com").unwrap_err();
    assert!(error.to_string().contains("member_id"));
}

#[test]
fn test_member_id_serde_roundtrip() {
    let member_id = MemberId::try_from("alice@example.com").unwrap();
    let encoded = serde_json::to_string(&member_id).unwrap();
    let decoded: MemberId = serde_json::from_str(&encoded).unwrap();

    assert_eq!(decoded, member_id);
}

#[test]
fn test_kid_try_from_normalizes_display_form() {
    let kid = Kid::try_from("rdkj-8yhm-ppjh-w7qc-3446-gpnx-hnrt-x61n").unwrap();
    assert_eq!(kid.as_str(), "RDKJ8YHMPPJHW7QC3446GPNXHNRTX61N");
}

#[test]
fn test_kid_try_from_invalid_error() {
    let error = Kid::try_from("INVALID").unwrap_err();
    assert!(error.to_string().contains("kid"));
}

#[test]
fn test_kid_serde_roundtrip() {
    let kid = Kid::try_from("RDKJ8YHMPPJHW7QC3446GPNXHNRTX61N").unwrap();
    let encoded = serde_json::to_string(&kid).unwrap();
    let decoded: Kid = serde_json::from_str(&encoded).unwrap();

    assert_eq!(decoded, kid);
}
