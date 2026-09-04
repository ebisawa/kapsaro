// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::test_utils::{with_temp_cwd, EnvGuard};

use super::resolution::resolve_optional_workspace;
use super::*;
use std::fs;

#[test]
fn resolve_optional_workspace_returns_none_when_nothing_is_configured() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_WORKSPACE"]);
    let temp_dir = tempfile::tempdir().unwrap();
    std::env::remove_var("KAPSARO_HOME");
    std::env::remove_var("KAPSARO_WORKSPACE");

    let result = with_temp_cwd(temp_dir.path(), || {
        resolve_optional_workspace(None).unwrap()
    });

    assert!(result.is_none());
}

#[test]
fn resolve_workspace_detects_current_dot_kapsaro_without_git() {
    let _guard = EnvGuard::new(&["KAPSARO_HOME", "KAPSARO_WORKSPACE"]);
    let temp_dir = tempfile::tempdir().unwrap();
    let workspace_path = temp_dir.path().join(".kapsaro");
    fs::create_dir_all(workspace_path.join("members/active")).unwrap();
    fs::create_dir_all(workspace_path.join("secrets")).unwrap();
    std::env::remove_var("KAPSARO_HOME");
    std::env::remove_var("KAPSARO_WORKSPACE");

    let result = with_temp_cwd(temp_dir.path(), || resolve_workspace(None).unwrap());

    assert_eq!(result.root_path, workspace_path.canonicalize().unwrap());
}

#[test]
fn resolve_optional_workspace_preserves_explicit_path_errors() {
    let missing = tempfile::tempdir()
        .unwrap()
        .path()
        .join("missing-workspace");
    let result = resolve_optional_workspace(Some(missing));
    assert!(result.is_err());
}
