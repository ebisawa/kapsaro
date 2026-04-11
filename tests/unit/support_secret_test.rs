// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;

use secretenv::support::secret::{SecretBytes, SecretString};
use zeroize::Zeroizing;

#[test]
fn test_secret_bytes_to_secret_string() {
    let bytes = SecretBytes::from_zeroizing(Zeroizing::new(b"super-secret".to_vec()));

    let secret = SecretString::try_from(bytes).expect("valid utf-8 should succeed");

    assert_eq!(secret.as_str(), "super-secret");
}

#[test]
fn test_secret_string_debug_is_redacted() {
    let secret = SecretString::new("super-secret".to_string());

    let debug = format!("{secret:?}");

    assert!(debug.contains("REDACTED"), "got: {debug}");
    assert!(!debug.contains("super-secret"), "got: {debug}");
}

#[test]
fn test_secret_string_into_os_string() {
    let secret = SecretString::new("super-secret".to_string());

    let os_string = secret.into_os_string();

    assert_eq!(os_string, OsString::from("super-secret"));
}
