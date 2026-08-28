// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for internal identity newtypes.

use kapsaro_core::cli_api::test_support::domain::identity::{Kid, MemberHandle};

#[test]
fn test_member_handle_try_from_valid() {
    let member_handle = MemberHandle::try_from("alice@example.com").unwrap();
    assert_eq!(member_handle.as_str(), "alice@example.com");
}

#[test]
fn test_member_handle_try_from_invalid_error() {
    let error = MemberHandle::try_from("@example.com").unwrap_err();
    assert!(error.to_string().contains("member_handle"));
}

#[test]
fn test_member_handle_serde_roundtrip() {
    let member_handle = MemberHandle::try_from("alice@example.com").unwrap();
    let encoded = serde_json::to_string(&member_handle).unwrap();
    let decoded: MemberHandle = serde_json::from_str(&encoded).unwrap();

    assert_eq!(decoded, member_handle);
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

#[test]
fn test_kid_deserialization_invalid_error() {
    let error = serde_json::from_str::<Kid>(r#""../../outside""#).unwrap_err();

    assert!(error.to_string().contains("kid"));
}

#[test]
fn test_kid_deserialization_requires_canonical_form() {
    let error =
        serde_json::from_str::<Kid>(r#""rdkj-8yhm-ppjh-w7qc-3446-gpnx-hnrt-x61n""#).unwrap_err();

    assert!(error.to_string().contains("canonical"), "{error}");
}

#[test]
fn test_kid_deserialization_error_carries_its_rule_code() {
    let error = serde_json::from_str::<Kid>(r#""INVALID""#).unwrap_err();

    assert!(error.to_string().contains("E_KID_INVALID"), "{error}");
}

#[test]
fn test_member_handle_deserialization_error_carries_its_rule_code() {
    let error = serde_json::from_str::<MemberHandle>(r#""../outside""#).unwrap_err();

    assert!(
        error.to_string().contains("E_MEMBER_HANDLE_INVALID"),
        "{error}"
    );
}

#[test]
fn test_kid_from_canonical_rejects_display_form_accepted_by_operator_input() {
    let display = "rdkj-8yhm-ppjh-w7qc-3446-gpnx-hnrt-x61n";

    let normalized = Kid::try_from(display).unwrap();
    let stored = Kid::from_canonical(display);

    assert_eq!(normalized.as_str(), "RDKJ8YHMPPJHW7QC3446GPNXHNRTX61N");
    assert!(stored.is_err());
    assert!(Kid::from_canonical(normalized.as_str()).is_ok());
}
