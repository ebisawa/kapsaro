// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for reading one value out of the global configuration.
//! Covers the value a configured key resolves to, an unset key, and key normalization.
//!
//! Every case names its base directory outright, which is the only thing that
//! decides which file is read here. Nothing on this path consults the
//! environment, so these tests neither guard a variable nor set one, and they
//! stay correct alongside a test that points `KAPSARO_HOME` somewhere else.

use crate::config::resolution::global::resolve_config_value;
use crate::io::config::store::set_config_value;
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::relative::DirectoryScope;
use crate::test_utils::local_state_temp_dir;
use tempfile::TempDir;

/// Open the local state root of `temp_dir` the way a write to it opens one.
fn open_local_state_home(temp_dir: &TempDir) -> AnchoredDir {
    AnchoredDir::open(
        temp_dir.path(),
        DirectoryScope::LocalState,
        "test local state root",
    )
    .unwrap()
}

#[test]
fn test_resolve_config_value_global() {
    let temp_dir = local_state_temp_dir();
    let home = open_local_state_home(&temp_dir);

    set_config_value(&home, "member_handle", "global@example.com").unwrap();

    let value = resolve_config_value("member_handle", Some(temp_dir.path())).unwrap();

    assert_eq!(value, Some("global@example.com".to_string()));
}

#[test]
fn test_resolve_workspace_config_value_global() {
    let temp_dir = local_state_temp_dir();
    let home = open_local_state_home(&temp_dir);

    set_config_value(&home, "workspace", "~/workspace/.kapsaro").unwrap();

    let value = resolve_config_value("workspace", Some(temp_dir.path())).unwrap();

    assert_eq!(value, Some("~/workspace/.kapsaro".to_string()));
}

/// A key the file says nothing about resolves to no value, which is what the
/// caller turns into its own "not configured" report.
#[test]
fn test_resolve_config_value_of_an_unset_key_is_none() {
    let temp_dir = local_state_temp_dir();
    let home = open_local_state_home(&temp_dir);

    set_config_value(&home, "member_handle", "global@example.com").unwrap();

    let value = resolve_config_value("workspace", Some(temp_dir.path())).unwrap();

    assert_eq!(value, None);
}

/// A spelling the configuration accepts as another name for a key reaches the
/// value stored under the canonical one, so callers hand over what the operator
/// typed without normalizing it first.
#[test]
fn test_resolve_config_value_reads_an_accepted_alias() {
    let temp_dir = local_state_temp_dir();
    let home = open_local_state_home(&temp_dir);

    set_config_value(&home, "github_user", "octocat").unwrap();

    let value = resolve_config_value("gihub_user", Some(temp_dir.path())).unwrap();

    assert_eq!(value, Some("octocat".to_string()));
}

/// A key the configuration does not support is rejected as an invalid argument
/// rather than answered as an unconfigured one.
#[test]
fn test_resolve_config_value_rejects_an_unsupported_key() {
    let temp_dir = local_state_temp_dir();

    let error = resolve_config_value("no_such_key", Some(temp_dir.path())).unwrap_err();

    assert!(error.to_string().contains("no_such_key"), "{error}");
}
