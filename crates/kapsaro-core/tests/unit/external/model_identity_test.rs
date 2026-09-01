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

const CANONICAL_KID: &str = "RDKJ8YHMPPJHW7QC3446GPNXHNRTX61N";

#[test]
fn test_kid_constructors_accept_canonical_form_without_rewriting() {
    let from_new = Kid::new(CANONICAL_KID).unwrap();
    let from_try_from = Kid::try_from(CANONICAL_KID).unwrap();

    assert_eq!(from_new.as_str(), CANONICAL_KID);
    assert_eq!(from_try_from.as_str(), CANONICAL_KID);
}

#[test]
fn test_kid_constructors_require_canonical_form() {
    for value in [
        "RDKJ-8YHM-PPJH-W7QC-3446-GPNX-HNRT-X61N",
        "rdkj8yhmppjhw7qc3446gpnxhnrtx61n",
        "RDKJ8YHM",
    ] {
        let new_error = Kid::new(value).unwrap_err();
        let try_from_error = Kid::try_from(value).unwrap_err();

        assert!(new_error.to_string().contains("canonical"), "{new_error}");
        assert!(
            try_from_error.to_string().contains("canonical"),
            "{try_from_error}"
        );
    }
}

#[test]
fn test_kid_try_from_invalid_error() {
    let error = Kid::try_from("INVALID").unwrap_err();
    assert!(error.to_string().contains("kid"));
}

#[test]
fn test_kid_serde_roundtrip() {
    let kid = Kid::try_from(CANONICAL_KID).unwrap();
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
    for value in [
        "RDKJ-8YHM-PPJH-W7QC-3446-GPNX-HNRT-X61N",
        "rdkj8yhmppjhw7qc3446gpnxhnrtx61n",
        "RDKJ8YHM",
    ] {
        let encoded = serde_json::to_string(value).unwrap();
        let error = serde_json::from_str::<Kid>(&encoded).unwrap_err();

        assert!(error.to_string().contains("canonical"), "{error}");
    }
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
