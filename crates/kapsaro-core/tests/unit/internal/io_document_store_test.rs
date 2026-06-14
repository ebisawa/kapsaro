// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::io::document_store::{
    CollectPermissionWarnings, DocumentStore, FailOnPermissionWarning,
};
use crate::support::fs::lock::with_locked_dir;
#[cfg(unix)]
use crate::support::fs::test_umask::{
    run_current_test_in_isolated_umask_process, with_restrictive_umask,
};
use crate::Result;
use std::cell::Cell;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

#[cfg(unix)]
#[test]
fn fail_on_permission_warning_rejects_before_parse() {
    let temp_dir = TempDir::new().unwrap();
    fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = temp_dir.path().join("secret.json");
    fs::write(&path, "{}").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let parser_called = Cell::new(false);

    let error = DocumentStore::<FailOnPermissionWarning>::load_required(
        &path,
        temp_dir.path(),
        1024,
        "secret document",
        |_| {
            parser_called.set(true);
            Ok(())
        },
    )
    .unwrap_err();

    assert!(!parser_called.get());
    assert!(error.to_string().contains("Insecure permissions"));
}

#[cfg(unix)]
#[test]
fn collect_permission_warnings_loads_document() {
    let temp_dir = TempDir::new().unwrap();
    fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = temp_dir.path().join("public.json");
    fs::write(&path, "loaded").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

    let loaded = DocumentStore::<CollectPermissionWarnings>::load_required(
        &path,
        temp_dir.path(),
        1024,
        "public document",
        parse_text,
    )
    .unwrap();

    assert_eq!(loaded.document, "loaded");
    assert_eq!(loaded.permission_warnings.len(), 1);
    assert!(loaded.permission_warnings[0].contains("Insecure permissions"));
}

#[cfg(unix)]
#[test]
fn save_json_restricted_at_preserves_0600_with_restrictive_umask() {
    const CHILD_ENV: &str = "KAPSARO_DOCUMENT_STORE_UMASK_CHILD";
    const TEST_NAME: &str =
        "io::document_store::tests::save_json_restricted_at_preserves_0600_with_restrictive_umask";
    if run_current_test_in_isolated_umask_process(CHILD_ENV, TEST_NAME) {
        return;
    }

    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("secret.json");
    let document = serde_json::json!({ "secret": "value" });

    with_restrictive_umask(|| {
        with_locked_dir(temp_dir.path(), |dir| {
            DocumentStore::<CollectPermissionWarnings>::save_json_restricted_at(
                dir, &path, &document,
            )
        })
        .unwrap();
    });

    let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn optional_load_returns_none_for_missing_document() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("missing.json");

    let loaded = DocumentStore::<CollectPermissionWarnings>::load_optional(
        &path,
        temp_dir.path(),
        1024,
        "public document",
        parse_text,
    )
    .unwrap();

    assert!(loaded.is_none());
}

fn parse_text(content: &str) -> Result<String> {
    Ok(content.to_string())
}
