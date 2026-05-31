// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn test_build_unsigned_kv_document_normal() {
    let result = build_unsigned_kv_document(
        "head_tok",
        "wrap_tok",
        &[("KEY1", "val1"), ("KEY2", "val2")],
    );
    assert_eq!(
        result,
        ":KAPSARO_KV 1\n:HEAD head_tok\n:WRAP wrap_tok\nKEY1 val1\nKEY2 val2\n"
    );
}

#[test]
fn test_build_unsigned_kv_document_empty_entries() {
    let result = build_unsigned_kv_document("head_tok", "wrap_tok", &[]);
    assert_eq!(result, ":KAPSARO_KV 1\n:HEAD head_tok\n:WRAP wrap_tok\n");
}
