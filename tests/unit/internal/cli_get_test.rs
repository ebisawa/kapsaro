// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use kapsaro_core::cli_api::app::kv::types::KvReadMode;

use super::resolve_get_read_mode;

#[test]
fn test_resolve_get_read_mode_rejects_all_with_key() {
    let Err(error) = resolve_get_read_mode(true, Some("API_KEY")) else {
        panic!("expected --all with KEY to fail");
    };

    assert!(error
        .format_user_message()
        .contains("--all and KEY argument cannot be used together"));
}

#[test]
fn test_resolve_get_read_mode_rejects_missing_key_without_all() {
    let Err(error) = resolve_get_read_mode(false, None) else {
        panic!("expected missing KEY to fail");
    };

    assert!(error
        .format_user_message()
        .contains("KEY argument is required"));
}

#[test]
fn test_resolve_get_read_mode_accepts_all() {
    let mode = resolve_get_read_mode(true, None).unwrap();

    assert!(matches!(mode, KvReadMode::All));
}

#[test]
fn test_resolve_get_read_mode_accepts_single_key() {
    let mode = resolve_get_read_mode(false, Some("API_KEY")).unwrap();

    match mode {
        KvReadMode::Single(key) => assert_eq!(key, "API_KEY"),
        KvReadMode::All => panic!("expected single key read mode"),
    }
}
