// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::fs;

#[test]
fn cli_api_test_support_is_hidden_and_feature_gated() {
    let content =
        fs::read_to_string("crates/secretenv-core/src/cli_api.rs").expect("read cli_api source");
    let test_support = test_support_section(&content);

    assert!(content.contains("#[cfg(any(feature = \"cli-test-support\", test))]"));
    assert!(content.contains("pub mod test_support {"));

    for new_root in [
        "pub mod settings {",
        "pub mod primitives {",
        "pub mod operations {",
        "pub mod wire {",
        "pub mod storage {",
        "pub mod domain {",
        "pub mod helpers {",
    ] {
        assert!(
            test_support.contains(new_root),
            "test_support is missing redesigned root: {new_root}"
        );
    }
}

#[test]
fn cli_api_uses_explicit_allow_lists() {
    let content =
        fs::read_to_string("crates/secretenv-core/src/cli_api.rs").expect("read cli_api source");

    assert!(content.contains("pub mod context {"));
    assert!(content.contains("pub mod file {"));
    assert!(content.contains("pub mod kv {"));
    assert!(content.contains("pub mod trust {"));
    assert!(content.contains("pub mod presentation {"));
    assert!(content.contains("pub mod file_content {"));
    assert!(content.contains("detect_file_enc_content_with_source"));
    assert!(content.contains("pub use crate::support::fs::atomic::{save_bytes, save_text};"));
    assert!(content.contains("pub mod test_support {"));
    assert!(content.contains("pub mod app {"));
}

fn test_support_section(content: &str) -> &str {
    content
        .split("#[cfg(any(feature = \"cli-test-support\", test))]")
        .nth(1)
        .expect("test_support cfg section")
}
