// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for the report a local trust store deletion leaves behind.
//! Covers the wording that has to name the removal before the failure after it.

use super::{describe_failure_after_trust_store_removal, report_quarantined_removal};
use crate::support::fs::relative::{open_dir_nofollow, DirectoryScope, OpenDir, RemovedEntry};
use crate::Error;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

const QUARANTINE_NAME: &str = ".alice@example.com.json.tmp.0000";
const STORE_NAME: &str = "alice@example.com.json";

/// The trust directory, with the confirmed document already moved aside in it.
fn quarantined_store(dir: &Path) -> OpenDir {
    fs::write(dir.join(QUARANTINE_NAME), "{}").unwrap();
    open_dir_nofollow(dir, DirectoryScope::Generic).unwrap()
}

fn store_path(dir: &Path) -> std::path::PathBuf {
    dir.join(STORE_NAME)
}

/// A failure that struck after the unlink has to say the store went first, or
/// the operator reads it as "the reset did not happen" and goes looking for
/// approvals that are already gone.
#[test]
fn test_failure_after_removal_reports_the_removal_first() {
    let message = describe_failure_after_trust_store_removal(
        std::path::Path::new("/tmp/.kapsaro/trust/alice@example.com.json"),
        "its directory entry was not persisted",
        &crate::Error::build_io_error("disk went away".to_string()),
    );

    assert!(message.contains("was removed"), "{message}");
    assert!(
        message.contains("its directory entry was not persisted"),
        "{message}"
    );
    assert!(message.contains("disk went away"), "{message}");
}

/// A removal that took the entry and only failed to persist the directory went,
/// so the report names the deletion that landed rather than the failure that
/// followed it.
#[test]
fn test_a_removal_that_was_not_persisted_reports_the_store_as_gone() {
    let temp_dir = TempDir::new().unwrap();
    let opened = quarantined_store(temp_dir.path());

    let error = report_quarantined_removal(
        &opened,
        QUARANTINE_NAME,
        &store_path(temp_dir.path()),
        STORE_NAME,
        Ok(RemovedEntry::Unpersisted(Error::build_io_error(
            "sync failed".to_string(),
        ))),
    )
    .expect_err("a removal that was not persisted has to be reported");

    let message = error.format_user_message();
    assert!(message.contains("was removed"), "{message}");
    assert!(message.contains("sync failed"), "{message}");
}

/// A removal that failed left the document standing under the name it was moved
/// to, holding approvals the reset did not discard, so the report names that
/// entry and the name it has to go back to.
#[test]
fn test_a_failed_removal_names_the_store_still_standing() {
    let temp_dir = TempDir::new().unwrap();
    let opened = quarantined_store(temp_dir.path());

    let error = report_quarantined_removal(
        &opened,
        QUARANTINE_NAME,
        &store_path(temp_dir.path()),
        STORE_NAME,
        Err(Error::build_io_error("unlink refused".to_string())),
    )
    .expect_err("a removal that did not land has to be reported");

    let message = error.format_user_message();
    assert!(message.contains("the deletion did not land"), "{message}");
    assert!(message.contains("unlink refused"), "{message}");
    assert!(message.contains(QUARANTINE_NAME), "{message}");
    assert!(message.contains(STORE_NAME), "{message}");
}

/// A removal that landed and was persisted is the reset going through.
#[test]
fn test_a_persisted_removal_reports_the_reset_as_done() {
    let temp_dir = TempDir::new().unwrap();
    let opened = quarantined_store(temp_dir.path());

    let removed = report_quarantined_removal(
        &opened,
        QUARANTINE_NAME,
        &store_path(temp_dir.path()),
        STORE_NAME,
        Ok(RemovedEntry::Persisted),
    )
    .unwrap();

    assert!(removed);
}
