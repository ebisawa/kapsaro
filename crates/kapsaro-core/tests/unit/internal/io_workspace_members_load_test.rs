// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the member document listing.
//! Covers which scanned entries the member store keeps and which end the listing.

use super::select_member_document_entries;
use crate::support::fs::relative::{ChildName, ChildType, EntryIdentity, ScannedChild};
use crate::Error;

#[cfg(unix)]
fn inspected(name: &[u8], child_type: ChildType) -> ScannedChild {
    ScannedChild::Inspected {
        name: ChildName::from_raw_bytes(name),
        child_type,
        mode: 0o600,
        owner: 0,
        identity: EntryIdentity::from_parts(1, 1),
    }
}

/// A filesystem may hold a name that is not UTF-8, and it names no member
/// document whatever it holds. It is passed over so that one unrelated file
/// dropped into the directory cannot hide every member the workspace has.
#[cfg(unix)]
#[test]
fn test_member_document_listing_passes_over_a_name_that_does_not_decode() {
    let children = vec![
        inspected(b"\xff\xfe", ChildType::RegularFile),
        inspected(b"alice.json", ChildType::RegularFile),
    ];

    let entries = select_member_document_entries(children).unwrap();

    assert_eq!(
        entries,
        vec![("alice.json".to_string(), ChildType::RegularFile)]
    );
}

/// A name that decodes but carries another extension is no member document
/// either, and it is left out the same way.
#[cfg(unix)]
#[test]
fn test_member_document_listing_keeps_only_the_member_document_spelling() {
    let children = vec![
        inspected(b"notes.txt", ChildType::RegularFile),
        inspected(b"bob.json", ChildType::RegularFile),
        inspected(b"alice.json", ChildType::Directory),
    ];

    let entries = select_member_document_entries(children).unwrap();

    assert_eq!(
        entries,
        vec![
            ("alice.json".to_string(), ChildType::Directory),
            ("bob.json".to_string(), ChildType::RegularFile),
        ]
    );
}

/// An entry that could not be inspected and does carry the member document
/// spelling may be a document, so the failure is reported rather than passed
/// over as though the directory held one member fewer.
#[cfg(unix)]
#[test]
fn test_member_document_listing_reports_an_entry_it_could_not_inspect() {
    let children = vec![ScannedChild::Unreadable {
        name: ChildName::from_raw_bytes(b"alice.json"),
        error: Error::build_io_error("permission denied".to_string()),
    }];

    let error = select_member_document_entries(children).unwrap_err();

    assert!(
        error.format_user_message().contains("permission denied"),
        "{}",
        error.format_user_message()
    );
}
