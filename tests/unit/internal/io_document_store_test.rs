// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::io::document_store::{
    CollectPermissionWarnings, DocumentStore, FailOnPermissionWarning,
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
