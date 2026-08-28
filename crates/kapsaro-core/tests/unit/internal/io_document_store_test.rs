// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::io::document_store;
#[cfg(unix)]
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::lock::lock_test_support::with_locked_workspace_dir;
use crate::support::fs::relative::{DirectoryFd, DirectoryScope};
#[cfg(unix)]
use crate::support::fs::test_umask::{isolated_umask_test, with_restrictive_umask};
#[cfg(unix)]
use crate::support::warning::LocalStateWarningGuard;
use crate::Result;
use std::cell::Cell;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

/// Every local state document is owner-only, so a group-readable one is loaded
/// with a warning naming it rather than refused.
#[cfg(unix)]
#[test]
fn test_document_store_warns_about_an_insecure_document_and_parses_it() {
    let temp_dir = TempDir::new().unwrap();
    fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = temp_dir.path().join("secret.json");
    fs::write(&path, "loaded").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let parser_called = Cell::new(false);
    let home = AnchoredDir::open(
        temp_dir.path(),
        DirectoryScope::LocalState,
        "test local state root",
    )
    .unwrap();

    let guard = LocalStateWarningGuard::new();
    let loaded =
        document_store::load_required_at(&home, &path, &[], 1024, "secret document", |content| {
            parser_called.set(true);
            parse_text(content)
        })
        .unwrap();
    let warnings = guard.take_reasons();

    assert!(parser_called.get());
    assert_eq!(loaded.document, "loaded");
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0].contains("Insecure permissions 0644"),
        "{warnings:?}"
    );
}

isolated_umask_test! {
    #[cfg(unix)]
    fn save_json_restricted_at_preserves_0600_with_restrictive_umask() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("secret.json");
        let document = serde_json::json!({ "secret": "value" });

        with_restrictive_umask(|| {
            with_locked_workspace_dir(temp_dir.path(), |dir| {
                document_store::save_json_restricted_at(dir, "secret.json", &document)
            })
            .unwrap();
        });

        let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn test_document_store_optional_load_returns_none_for_a_missing_document() {
    let temp_dir = TempDir::new().unwrap();
    let path = temp_dir.path().join("missing.json");

    let loaded = with_locked_workspace_dir(temp_dir.path(), |dir| {
        document_store::load_optional_at(dir, &path, &[], 1024, "public document", parse_text)
    })
    .unwrap();

    assert!(loaded.is_none());
}

/// Open a local state root that group and other can reach, the way a home
/// created under the usual umask is left.
#[cfg(unix)]
fn open_group_readable_local_state_root(temp_dir: &TempDir) -> AnchoredDir {
    fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    AnchoredDir::open(
        temp_dir.path(),
        DirectoryScope::LocalState,
        "test local state root",
    )
    .unwrap()
}

/// The permission rule covers the directories a document is reached through as
/// well as the document itself, and those directories are reused whether or not
/// the optional document standing in them exists. An exposed local state root
/// is reported even where the read finds nothing to load.
#[cfg(unix)]
#[test]
fn test_document_store_optional_load_inspects_the_ancestry_of_an_absent_document() {
    let temp_dir = TempDir::new().unwrap();
    let home = open_group_readable_local_state_root(&temp_dir);
    let permission_chain: [&dyn DirectoryFd; 1] = [&home];
    let path = temp_dir.path().join("config.toml");

    let guard = LocalStateWarningGuard::new();
    let loaded = document_store::load_optional_at(
        &home,
        &path,
        &permission_chain,
        1024,
        "config document",
        parse_text,
    )
    .unwrap();
    let reason = guard.take_single_reason_under(temp_dir.path());

    assert!(loaded.is_none());
    assert!(reason.contains("Insecure permissions 0755"), "{reason}");
}

/// The loader that keeps the source text answers an absent document the same
/// way, so which loader a caller picked never decides whether the directories
/// above the document are inspected.
#[cfg(unix)]
#[test]
fn test_document_store_raw_retaining_optional_load_inspects_the_ancestry_of_an_absent_document() {
    let temp_dir = TempDir::new().unwrap();
    let home = open_group_readable_local_state_root(&temp_dir);
    let permission_chain: [&dyn DirectoryFd; 1] = [&home];
    let path = temp_dir.path().join("trust.json");

    let guard = LocalStateWarningGuard::new();
    let loaded = document_store::load_optional_with_raw_at(
        &home,
        &path,
        &permission_chain,
        1024,
        "trust document",
        parse_text,
    )
    .unwrap();
    let reason = guard.take_single_reason_under(temp_dir.path());

    assert!(loaded.is_none());
    assert!(reason.contains("Insecure permissions 0755"), "{reason}");
}

/// One command reads several documents out of the same directory, and the
/// operator has one entry to repair. The directory is named once however many
/// reads met it.
#[cfg(unix)]
#[test]
fn test_document_store_reports_one_exposed_directory_once_across_several_reads() {
    let temp_dir = TempDir::new().unwrap();
    let home = open_group_readable_local_state_root(&temp_dir);
    let permission_chain: [&dyn DirectoryFd; 1] = [&home];
    let absent = temp_dir.path().join("absent.json");
    let present = temp_dir.path().join("present.json");
    fs::write(&present, "loaded").unwrap();
    fs::set_permissions(&present, fs::Permissions::from_mode(0o600)).unwrap();

    let guard = LocalStateWarningGuard::new();
    for path in [&absent, &present] {
        let loaded = document_store::load_optional_at(
            &home,
            path,
            &permission_chain,
            1024,
            "local state document",
            parse_text,
        )
        .unwrap();
        assert_eq!(loaded.is_some(), path == &present);
    }
    let reason = guard.take_single_reason_under(temp_dir.path());

    assert!(reason.contains("Insecure permissions 0755"), "{reason}");
}

/// Whoever can write a directory chooses the names in it, so a name the loader
/// cannot decode is spelled out rather than passed on as it stands: a newline in
/// one would otherwise forge a second line of the report it lands in.
#[cfg(unix)]
#[test]
fn test_document_store_spells_out_control_characters_in_an_undecodable_path() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let path = std::path::Path::new("/nonexistent").join(OsStr::from_bytes(b"bad\nname\xFF"));

    let error = document_store::file_name(&path).unwrap_err();

    let message = error.format_user_message();
    assert!(message.contains("bad\\nname"), "{message}");
    assert!(!message.contains("bad\nname"), "{message}");
}

fn parse_text(content: &str) -> Result<String> {
    Ok(content.to_string())
}

fn fail_to_parse(_content: &str) -> Result<String> {
    Err(crate::Error::build_config_error(
        "document is not valid JSON".to_string(),
    ))
}

/// A parse failure must not leave the source text reachable: it is neither
/// returned as `raw_content` nor echoed back in the error message.
#[cfg(unix)]
#[test]
fn test_document_store_default_load_on_parse_failure_does_not_leak_the_source_text() {
    let temp_dir = TempDir::new().unwrap();
    fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = temp_dir.path().join("private.json");
    fs::write(&path, "private-key-material").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    let error = with_locked_workspace_dir(temp_dir.path(), |dir| {
        document_store::load_required_at(dir, &path, &[], 1024, "private document", fail_to_parse)
    })
    .unwrap_err();

    let message = error.to_string();
    assert!(!message.contains("private-key-material"), "{message}");
}

#[cfg(unix)]
#[test]
fn test_document_store_default_load_discards_the_serialized_source_text() {
    let temp_dir = TempDir::new().unwrap();
    fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = temp_dir.path().join("private.json");
    fs::write(&path, "private-key-material").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    let loaded = with_locked_workspace_dir(temp_dir.path(), |dir| {
        document_store::load_required_at(dir, &path, &[], 1024, "private document", parse_text)
    })
    .unwrap();

    assert_eq!(loaded.document, "private-key-material");
    assert_eq!(
        loaded.raw_content, None,
        "key documents must not carry their plaintext past parsing"
    );
}

#[cfg(unix)]
#[test]
fn test_document_store_raw_retaining_load_keeps_the_serialized_source_text() {
    let temp_dir = TempDir::new().unwrap();
    fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = temp_dir.path().join("trust.json");
    fs::write(&path, "reviewed-bytes").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    let loaded = with_locked_workspace_dir(temp_dir.path(), |dir| {
        document_store::load_required_with_raw_at(
            dir,
            &path,
            &[],
            1024,
            "trust document",
            parse_text,
        )
    })
    .unwrap();

    assert_eq!(loaded.raw_content.as_deref(), Some("reviewed-bytes"));
}
