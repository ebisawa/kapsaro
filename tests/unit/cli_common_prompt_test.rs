// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::prompt_yes_no_with_reader;
use std::io::Cursor;

#[test]
fn test_prompt_yes_no_with_reader_accepts_yes() {
    let accepted =
        prompt_yes_no_with_reader("Proceed?", false, Cursor::new(b"y\n".to_vec())).unwrap();

    assert!(accepted);
}

#[test]
fn test_prompt_yes_no_with_reader_uses_default_for_empty_input() {
    let accepted =
        prompt_yes_no_with_reader("Proceed?", true, Cursor::new(b"\n".to_vec())).unwrap();

    assert!(accepted);
}

#[test]
fn test_prompt_yes_no_with_reader_rejects_non_yes_input() {
    let accepted =
        prompt_yes_no_with_reader("Proceed?", false, Cursor::new(b"no\n".to_vec())).unwrap();

    assert!(!accepted);
}
