// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for kid helpers.

use secretenv::format::kid::derive_public_key_kid;
use secretenv::support::kid::{
    format_kid_display, format_kid_half_display, normalize_kid, normalize_kid_query,
    resolve_unique_kid,
};
use serde_json::json;

const CANONICAL_KID: &str = "F0B1CQRGA0Y5C03XDRDMPMTMXNWAQZVG";
const DISPLAY_KID: &str = "F0B1-CQRG-A0Y5-C03X-DRDM-PMTM-XNWA-QZVG";
const HALF_DISPLAY_KID: &str = "F0B1-CQRG-A0Y5-C03X";

#[test]
fn test_normalize_kid_accepts_display_and_lowercase_forms() {
    assert_eq!(normalize_kid(CANONICAL_KID).unwrap(), CANONICAL_KID);
    assert_eq!(
        normalize_kid(&CANONICAL_KID.to_lowercase()).unwrap(),
        CANONICAL_KID
    );
    assert_eq!(normalize_kid(DISPLAY_KID).unwrap(), CANONICAL_KID);
}

#[test]
fn test_normalize_kid_rejects_invalid_length() {
    let error = normalize_kid("ABC123").unwrap_err();
    assert!(
        error.to_string().contains("kid"),
        "error should mention kid: {error}"
    );
}

#[test]
fn test_normalize_kid_query_accepts_prefix_and_display_form() {
    assert_eq!(normalize_kid_query("f0b1-cq").unwrap(), "F0B1CQ");
    assert_eq!(normalize_kid_query("83").unwrap(), "83");
}

#[test]
fn test_resolve_unique_kid_accepts_unique_prefix() {
    let candidates = [
        "F0B1CQRGA0Y5C03XDRDMPMTMXNWAQZVG",
        "83ZZEQ3M7S8KHTT3WAA8DW46QYTA93XE",
    ];

    let resolved = resolve_unique_kid(candidates, "f0b1-cq").unwrap();

    assert_eq!(resolved, CANONICAL_KID);
}

#[test]
fn test_resolve_unique_kid_rejects_ambiguous_prefix() {
    let candidates = [
        "83KJ8YHMPPJHW7QC3446GPNXHNRTX61N",
        "83ZZ8YHMPPJHW7QC3446GPNXHNRTX61N",
    ];

    let error = resolve_unique_kid(candidates, "83").unwrap_err();

    assert!(
        error.to_string().contains("ambiguous"),
        "error should mention ambiguity: {error}"
    );
}

#[test]
fn test_format_kid_display_groups_canonical_form_by_four() {
    assert_eq!(format_kid_display(CANONICAL_KID).unwrap(), DISPLAY_KID);
}

#[test]
fn test_format_kid_half_display_uses_first_four_groups() {
    assert_eq!(
        format_kid_half_display(CANONICAL_KID).unwrap(),
        HALF_DISPLAY_KID
    );
}

#[test]
fn test_format_kid_display_rejects_invalid_canonical_value() {
    let error = format_kid_display("INVALID").unwrap_err();
    assert!(
        error.to_string().contains("kid"),
        "error should mention kid: {error}"
    );
}

#[test]
fn test_derive_public_key_kid_matches_spec_vector() {
    let protected_without_kid = json!({
        "format": "secretenv:format:public-key@6",
        "subject_handle": "alice@example.com",
        "identity": {
            "keys": {
                "kem": {
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                },
                "sig": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
                }
            },
            "attestation": {
                "method": "ssh-sign",
                "pub": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey alice@example.com",
                "sig": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
            }
        },
        "binding_claims": {
            "github_account": {
                "id": 12345,
                "login": "alice-gh"
            }
        },
        "expires_at": "2027-01-14T00:00:00Z",
        "created_at": "2026-01-14T00:00:00Z"
    });

    assert_eq!(
        derive_public_key_kid(&protected_without_kid).unwrap(),
        CANONICAL_KID
    );
}

#[test]
fn test_derive_public_key_kid_changes_when_binding_claims_change() {
    let protected_without_kid = json!({
        "format": "secretenv:format:public-key@6",
        "subject_handle": "alice@example.com",
        "identity": {
            "keys": {
                "kem": {
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                },
                "sig": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
                }
            },
            "attestation": {
                "method": "ssh-sign",
                "pub": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey alice@example.com",
                "sig": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
            }
        },
        "binding_claims": {
            "github_account": {
                "id": 12345,
                "login": "alice-gh"
            }
        },
        "expires_at": "2027-01-14T00:00:00Z",
        "created_at": "2026-01-14T00:00:00Z"
    });
    let changed_binding_claims = json!({
        "format": "secretenv:format:public-key@6",
        "subject_handle": "alice@example.com",
        "identity": {
            "keys": {
                "kem": {
                    "kty": "OKP",
                    "crv": "X25519",
                    "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                },
                "sig": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
                }
            },
            "attestation": {
                "method": "ssh-sign",
                "pub": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey alice@example.com",
                "sig": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
            }
        },
        "binding_claims": {
            "github_account": {
                "id": 12345,
                "login": "alice-gh-rotated"
            }
        },
        "expires_at": "2027-01-14T00:00:00Z",
        "created_at": "2026-01-14T00:00:00Z"
    });

    assert_ne!(
        derive_public_key_kid(&protected_without_kid).unwrap(),
        derive_public_key_kid(&changed_binding_claims).unwrap()
    );
}
