// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the umask isolation helper's child detection and test naming.
//! Covers the filter string handed to the child and the marker value it accepts.

use crate::support::fs::test_umask::{
    instruction_names_this_test, qualified_test_name, UmaskChildInstruction,
};
use std::ffi::OsString;
use std::path::PathBuf;
use tempfile::TempDir;

const NONCE: &str = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";

/// Stand in for the parent: leave the nonce beside the marker it will name.
fn issue_nonce(dir: &TempDir, nonce: &str) -> PathBuf {
    std::fs::write(dir.path().join("nonce"), nonce).unwrap();
    dir.path().join("completed")
}

#[test]
fn qualified_test_name_drops_the_crate_prefix_module_path_adds() {
    assert_eq!(
        qualified_test_name("kapsaro_core::io::document_store::tests", "saves_the_file"),
        "io::document_store::tests::saves_the_file"
    );
}

#[test]
fn qualified_test_name_keeps_the_bare_name_when_no_module_qualifies_it() {
    assert_eq!(
        qualified_test_name("kapsaro_core", "saves_the_file"),
        "saves_the_file"
    );
}

#[test]
fn umask_child_instruction_round_trips_the_test_name_and_marker() {
    let dir = TempDir::new().unwrap();
    let marker = issue_nonce(&dir, NONCE);

    let decoded = UmaskChildInstruction::decode(&UmaskChildInstruction::encode(
        NONCE,
        "support::fs::tests::writes",
        &marker,
    ))
    .expect("a value this helper wrote must decode");

    assert_eq!(decoded.test_name(), "support::fs::tests::writes");
    assert_eq!(decoded.marker(), marker);
}

/// The child branch changes the umask of the whole process, and the umask
/// decides the mode of every file the tests running beside it create. A
/// variable of the same name from outside the test run must therefore never
/// pass for an instruction this helper wrote.
#[test]
fn umask_child_instruction_rejects_a_value_this_helper_did_not_write() {
    let dir = TempDir::new().unwrap();
    let marker = issue_nonce(&dir, NONCE);
    let marker = marker.display();
    for foreign in [
        "/tmp/marker/completed".to_string(),
        "kapsaro-umask-child".to_string(),
        format!("kapsaro-umask-child\u{1f}not-a-uuid\u{1f}some::test\u{1f}{marker}"),
        format!("other-tool\u{1f}{NONCE}\u{1f}some::test\u{1f}{marker}"),
    ] {
        assert!(
            UmaskChildInstruction::decode(&OsString::from(&foreign)).is_none(),
            "must not be taken for a child instruction: {foreign}"
        );
    }
}

/// A well-formed value carrying a nonce the parent never issued is the shape an
/// outside variable would take, so the nonce is checked against the one left
/// beside the marker rather than against the shape of a UUID.
#[test]
fn umask_child_instruction_rejects_a_nonce_the_parent_never_issued() {
    let dir = TempDir::new().unwrap();
    let marker = issue_nonce(&dir, NONCE);
    let foreign = UmaskChildInstruction::encode(
        "9f8b1d2c-0000-4a3b-8c1d-2f4e6a8b0c1d",
        "support::fs::tests::writes",
        &marker,
    );

    assert!(UmaskChildInstruction::decode(&foreign).is_none());
}

/// A marker naming a directory the parent never created carries no nonce at
/// all, which is what an inherited variable pointing anywhere else looks like.
#[test]
fn umask_child_instruction_rejects_a_marker_with_no_issued_nonce() {
    let dir = TempDir::new().unwrap();
    let marker = dir.path().join("completed");

    let value = UmaskChildInstruction::encode(NONCE, "support::fs::tests::writes", &marker);

    assert!(UmaskChildInstruction::decode(&value).is_none());
}

/// The instruction names one test, and only that test may take the child
/// branch. A child filtered to a different test would otherwise run its body
/// under a umask nobody asked for.
#[test]
fn umask_child_instruction_carries_the_test_it_was_spawned_for() {
    let dir = TempDir::new().unwrap();
    let marker = issue_nonce(&dir, NONCE);

    let decoded = UmaskChildInstruction::decode(&UmaskChildInstruction::encode(
        NONCE,
        "support::fs::tests::writes",
        &marker,
    ))
    .expect("a value this helper wrote must decode");

    assert_eq!(decoded.test_name(), "support::fs::tests::writes");
}

/// Only the instruction whose named test matches the running test may take the
/// child branch; any other named test must be rejected so it falls back to
/// spawning its own child instead of running under a umask meant for someone
/// else.
#[test]
fn instruction_names_this_test_matches_only_the_named_test() {
    let dir = TempDir::new().unwrap();
    let marker = issue_nonce(&dir, NONCE);

    let decoded = UmaskChildInstruction::decode(&UmaskChildInstruction::encode(
        NONCE,
        "support::fs::tests::writes",
        &marker,
    ))
    .expect("a value this helper wrote must decode");

    assert!(instruction_names_this_test(
        &decoded,
        "support::fs::tests::writes"
    ));
    assert!(!instruction_names_this_test(
        &decoded,
        "support::fs::tests::reads"
    ));
}
