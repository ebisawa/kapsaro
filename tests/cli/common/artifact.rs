// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

// Artifact manipulation, assertion helpers, and file utilities for CLI integration tests.
// Provides KV signature tampering and stderr ordering assertions.

use kapsaro_core::cli_api::test_support::helpers::codec::base64_public::encode_base64url_nopad;
use kapsaro_core::cli_api::test_support::wire::schema::document::parse_kv_signature_token;
use kapsaro_core::cli_api::test_support::wire::token::TokenCodec;
use std::path::Path;

/// Overwrites the signature in a kv-enc file with zeroed bytes to simulate tampering.
pub fn tamper_kv_signature(path: &Path) {
    let content = std::fs::read_to_string(path).expect("kv-enc file must be readable");
    let mut lines = Vec::new();
    let mut tampered = false;
    for line in content.lines() {
        if let Some(token) = line.strip_prefix(":SIG ") {
            let mut signature =
                parse_kv_signature_token(token).expect("kv-enc signature token must parse");
            signature.sig = encode_base64url_nopad(&[0u8; 64]);
            let token = TokenCodec::encode(TokenCodec::JsonJcs, &signature)
                .expect("tampered signature token must encode");
            lines.push(format!(":SIG {token}"));
            tampered = true;
        } else {
            lines.push(line.to_string());
        }
    }
    assert!(tampered, "kv-enc file must contain a SIG line");
    std::fs::write(path, format!("{}\n", lines.join("\n"))).expect("kv-enc file must be writable");
}

/// Asserts that `first` appears before `second` in the given stderr bytes.
pub fn assert_stderr_order(stderr: &[u8], first: &str, second: &str) {
    let stderr = String::from_utf8_lossy(stderr);
    let first_index = stderr
        .find(first)
        .unwrap_or_else(|| panic!("Missing '{first}' in stderr: {stderr}"));
    let second_index = stderr
        .find(second)
        .unwrap_or_else(|| panic!("Missing '{second}' in stderr: {stderr}"));
    assert!(
        first_index < second_index,
        "Expected '{first}' before '{second}' in stderr: {stderr}"
    );
}
