// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Internal tests for turning a dotenv document into KV write entries.
//! Covers the order the entries come out in and the documents that are refused.

use crate::feature::kv::import::parse_dotenv_entries;
use crate::feature::kv::types::KvInputEntry;
use crate::ErrorKind;

/// The lenient parser hands back an unordered map, so the entries are sorted by
/// key before they are written. Two keys typed in the opposite order state that.
#[test]
fn test_parse_dotenv_entries_orders_entries_by_key() {
    let entries = parse_dotenv_entries("ZEBRA=last\nALPHA=first\n").unwrap();

    assert_eq!(
        entries,
        vec![
            KvInputEntry::new("ALPHA", "first"),
            KvInputEntry::new("ZEBRA", "last"),
        ]
    );
}

/// A shell-ready document prefixes each assignment with `export`, and the
/// prefix names no part of the key.
#[test]
fn test_parse_dotenv_entries_accepts_an_export_prefix() {
    let entries = parse_dotenv_entries("export TOKEN=\"secret value\"\n").unwrap();

    assert_eq!(entries, vec![KvInputEntry::new("TOKEN", "secret value")]);
}

/// The lenient parser drops a line without a separator, which would import
/// fewer entries than the document names. The import refuses the document
/// instead, and the message points at the line rather than repeating its body.
#[test]
fn test_parse_dotenv_entries_rejects_a_line_without_a_separator_error() {
    let error = parse_dotenv_entries("KEY=value\nNOT_AN_ENTRY\n").unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(
        error.to_string().contains("Line 2: missing '=' separator"),
        "unexpected message: {error}"
    );
}

#[test]
fn test_parse_dotenv_entries_rejects_an_invalid_key_name_error() {
    let error = parse_dotenv_entries("123KEY=value\n").unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(
        error.to_string().contains("invalid key name"),
        "unexpected message: {error}"
    );
}

/// A document holding only comments and blank lines would import nothing, so it
/// is reported rather than written as an empty change.
#[test]
fn test_parse_dotenv_entries_rejects_a_document_without_entries_error() {
    let error = parse_dotenv_entries("# only a comment\n\n").unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(
        error.to_string().contains("No valid entries found"),
        "unexpected message: {error}"
    );
}

#[test]
fn test_parse_dotenv_entries_rejects_empty_content_error() {
    let error = parse_dotenv_entries("").unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(
        error.to_string().contains("No valid entries found"),
        "unexpected message: {error}"
    );
}
