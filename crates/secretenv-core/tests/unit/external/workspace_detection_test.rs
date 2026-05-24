// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for workspace detection (Phase 5.5 - TDD Red phase)

use crate::test_utils::EnvGuard;
use secretenv_core::cli_api::test_support::storage::workspace::detection::{
    detect_workspace_root, resolve_workspace,
};
use serial_test::serial;
use std::env;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Helper to create a workspace structure
fn build_workspace(root: &TempDir) -> (PathBuf, PathBuf) {
    let repo_root = root.path().canonicalize().unwrap();
    fs::create_dir_all(repo_root.join(".git")).unwrap();

    let workspace_root = repo_root.join(".secretenv");
    fs::create_dir_all(workspace_root.join("members/active")).unwrap();
    fs::create_dir_all(workspace_root.join("secrets")).unwrap();

    (repo_root, workspace_root)
}

#[test]
fn test_detect_workspace_in_current_directory() {
    let temp = TempDir::new().unwrap();
    let (repo_root, workspace_root) = build_workspace(&temp);

    let result = detect_workspace_root(&repo_root);
    assert!(result.is_ok());
    let workspace = result.unwrap();
    assert_eq!(workspace.root_path, workspace_root);
}

#[test]
fn test_detect_workspace_in_parent_directory() {
    let temp = TempDir::new().unwrap();
    let (repo_root, workspace_root) = build_workspace(&temp);

    // Create a subdirectory
    let sub_dir = repo_root.join("subdir");
    fs::create_dir(&sub_dir).unwrap();

    let result = detect_workspace_root(&sub_dir);
    assert!(result.is_ok());
    let workspace = result.unwrap();
    assert_eq!(workspace.root_path, workspace_root);
}

#[test]
fn test_detect_workspace_without_git_uses_current_dot_secretenv() {
    let temp = TempDir::new().unwrap();
    let root_path = temp.path().canonicalize().unwrap();
    let workspace_root = root_path.join(".secretenv");
    fs::create_dir_all(workspace_root.join("members/active")).unwrap();
    fs::create_dir_all(workspace_root.join("secrets")).unwrap();

    let result = detect_workspace_root(&root_path);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().root_path, workspace_root);
}

#[test]
fn test_detect_workspace_without_git_does_not_search_parent() {
    let temp = TempDir::new().unwrap();
    let root_path = temp.path().canonicalize().unwrap();
    let workspace_root = root_path.join(".secretenv");
    fs::create_dir_all(workspace_root.join("members/active")).unwrap();
    fs::create_dir_all(workspace_root.join("secrets")).unwrap();

    let sub_dir = root_path.join("subdir");
    fs::create_dir(&sub_dir).unwrap();

    let result = detect_workspace_root(&sub_dir);
    assert!(result.is_err());
}

#[test]
fn test_detect_workspace_with_marker_file() {
    let temp = TempDir::new().unwrap();
    let (repo_root, workspace_root) = build_workspace(&temp);

    // Create .secretenv-root marker
    fs::write(workspace_root.join(".secretenv-root"), "").unwrap();

    let result = detect_workspace_root(&repo_root);
    assert!(result.is_ok());
    let workspace = result.unwrap();
    assert_eq!(workspace.root_path, workspace_root);
    assert!(workspace.has_marker_file);
}

#[test]
fn test_detect_workspace_with_toml_config() {
    let temp = TempDir::new().unwrap();
    let (repo_root, workspace_root) = build_workspace(&temp);

    // Create config.toml
    fs::write(
        workspace_root.join("config.toml"),
        r#"
[workspace]
mode = "git"
"#,
    )
    .unwrap();

    let result = detect_workspace_root(&repo_root);
    assert!(result.is_ok());
    let workspace = result.unwrap();
    assert_eq!(workspace.root_path, workspace_root);
}

#[test]
fn test_detect_workspace_fails_without_members_directory() {
    let temp = TempDir::new().unwrap();
    let root_path = temp.path();
    fs::create_dir_all(root_path.join(".git")).unwrap();

    // Only create secrets directory
    fs::create_dir_all(root_path.join("secrets")).unwrap();

    let result = detect_workspace_root(root_path);
    assert!(result.is_err());
}

#[test]
fn test_detect_workspace_fails_without_secrets_directory() {
    let temp = TempDir::new().unwrap();
    let root_path = temp.path();
    fs::create_dir_all(root_path.join(".git")).unwrap();

    // Only create members directory (without active/ subdir and without secrets/)
    fs::create_dir_all(root_path.join("members")).unwrap();

    let result = detect_workspace_root(root_path);
    assert!(result.is_err());
}

#[test]
fn test_detect_workspace_stops_at_marker() {
    let temp = TempDir::new().unwrap();
    let (outer_repo_root, _outer_workspace_root) = build_workspace(&temp);

    // Create marker at outer root
    fs::write(outer_repo_root.join(".secretenv-root"), "").unwrap();

    // Create inner workspace
    let inner_dir = outer_repo_root.join("inner");
    fs::create_dir(&inner_dir).unwrap();
    fs::create_dir_all(inner_dir.join(".secretenv/members/active")).unwrap();
    fs::create_dir_all(inner_dir.join(".secretenv/secrets")).unwrap();

    // Detection from inner should find inner workspace first
    let result = detect_workspace_root(&inner_dir);
    assert!(result.is_ok());
    let workspace = result.unwrap();
    assert_eq!(
        workspace.root_path,
        inner_dir.join(".secretenv").canonicalize().unwrap()
    );
}

#[test]
fn test_workspace_root_fields() {
    let temp = TempDir::new().unwrap();
    let (repo_root, workspace_root) = build_workspace(&temp);
    fs::write(workspace_root.join(".secretenv-root"), "").unwrap();
    fs::write(
        workspace_root.join("config.toml"),
        "[workspace]\nmode = \"auto\"",
    )
    .unwrap();

    let result = detect_workspace_root(&repo_root);
    assert!(result.is_ok());
    let workspace = result.unwrap();

    assert_eq!(workspace.root_path, workspace_root);
    assert!(workspace.has_marker_file);
    assert_eq!(workspace.members_dir(), workspace_root.join("members"));
    assert_eq!(workspace.secrets_dir(), workspace_root.join("secrets"));
}

// Phase 1.3 tests: explicit path validation and auto-detection

#[test]
fn test_resolve_workspace_with_explicit_option() {
    let _guard = EnvGuard::new(&["SECRETENV_WORKSPACE"]);

    let temp = TempDir::new().unwrap();
    let (_repo_root, root_path) = build_workspace(&temp);

    // Set environment variable to different path
    let temp2 = TempDir::new().unwrap();
    let (_repo_root2, env_path) = build_workspace(&temp2);
    env::set_var("SECRETENV_WORKSPACE", &env_path);

    // Explicit option should take priority over environment variable
    let result = resolve_workspace(Some(root_path.clone()));
    assert!(result.is_ok());
    let workspace = result.unwrap();
    assert_eq!(workspace.root_path, root_path);
}

#[test]
#[serial]
fn test_resolve_workspace_ignores_environment_variable() {
    let _guard = EnvGuard::new(&["SECRETENV_WORKSPACE"]);
    let original_dir = env::current_dir().unwrap();
    let current = TempDir::new().unwrap();
    let env_workspace = TempDir::new().unwrap();
    let (_repo_root, env_path) = build_workspace(&env_workspace);
    env::set_var("SECRETENV_WORKSPACE", &env_path);
    env::set_current_dir(current.path()).unwrap();

    let result = resolve_workspace(None);
    assert!(result.is_err());

    env::set_current_dir(original_dir).unwrap();
}

#[test]
#[serial]
fn test_resolve_workspace_fallback_to_search() {
    let _guard = EnvGuard::new(&["SECRETENV_WORKSPACE"]);

    let temp = TempDir::new().unwrap();
    let (repo_root, workspace_root) = build_workspace(&temp);

    // Create subdirectory
    let sub_dir = repo_root.join("subdir");
    fs::create_dir(&sub_dir).unwrap();

    // No option, no env var, should search from current directory
    // We need to change directory for this test
    let original_dir = env::current_dir().unwrap();
    env::set_current_dir(&sub_dir).unwrap();

    // Ensure no environment variable is set
    env::remove_var("SECRETENV_WORKSPACE");

    let result = resolve_workspace(None);
    assert!(result.is_ok());
    let workspace = result.unwrap();
    assert_eq!(workspace.root_path, workspace_root);

    // Restore original directory
    env::set_current_dir(original_dir).unwrap();
}

#[test]
fn test_detect_workspace_in_git_worktree() {
    let temp = TempDir::new().unwrap();
    let main_repo = temp.path().canonicalize().unwrap();

    // Main repository with .git directory and .secretenv workspace
    fs::create_dir_all(main_repo.join(".git/worktrees/my-worktree")).unwrap();
    fs::create_dir_all(main_repo.join(".secretenv/members/active")).unwrap();
    fs::create_dir_all(main_repo.join(".secretenv/secrets")).unwrap();

    // Worktree directory (outside or inside main repo, with .git file)
    let worktree_parent = TempDir::new().unwrap();
    let worktree_dir = worktree_parent.path().join("my-worktree");
    fs::create_dir_all(&worktree_dir).unwrap();

    // .git file pointing back to main repo's worktree directory
    let gitdir_path = main_repo.join(".git/worktrees/my-worktree");
    fs::write(
        worktree_dir.join(".git"),
        format!("gitdir: {}", gitdir_path.display()),
    )
    .unwrap();

    // commondir file in the worktree git directory, pointing to main .git
    fs::write(
        gitdir_path.join("commondir"),
        main_repo.join(".git").to_str().unwrap(),
    )
    .unwrap();

    let result = detect_workspace_root(&worktree_dir);
    assert!(
        result.is_ok(),
        "Should detect workspace through git worktree, but got: {:?}",
        result.err()
    );
    let workspace = result.unwrap();
    let expected = main_repo.join(".secretenv").canonicalize().unwrap();
    assert_eq!(workspace.root_path, expected);
}

#[test]
fn test_detect_workspace_in_git_worktree_from_subdirectory() {
    let temp = TempDir::new().unwrap();
    let main_repo = temp.path().canonicalize().unwrap();

    // Main repository with workspace
    fs::create_dir_all(main_repo.join(".git/worktrees/my-worktree")).unwrap();
    fs::create_dir_all(main_repo.join(".secretenv/members/active")).unwrap();
    fs::create_dir_all(main_repo.join(".secretenv/secrets")).unwrap();

    // Worktree directory with subdirectory
    let worktree_parent = TempDir::new().unwrap();
    let worktree_dir = worktree_parent.path().join("my-worktree");
    let sub_dir = worktree_dir.join("src/deep/nested");
    fs::create_dir_all(&sub_dir).unwrap();

    let gitdir_path = main_repo.join(".git/worktrees/my-worktree");
    fs::write(
        worktree_dir.join(".git"),
        format!("gitdir: {}", gitdir_path.display()),
    )
    .unwrap();
    fs::write(
        gitdir_path.join("commondir"),
        main_repo.join(".git").to_str().unwrap(),
    )
    .unwrap();

    // Search from a deeply nested subdirectory within the worktree
    let result = detect_workspace_root(&sub_dir);
    assert!(
        result.is_ok(),
        "Should detect workspace from worktree subdirectory, but got: {:?}",
        result.err()
    );
    let workspace = result.unwrap();
    let expected = main_repo.join(".secretenv").canonicalize().unwrap();
    assert_eq!(workspace.root_path, expected);
}

#[test]
fn test_check_workspace_secretenv_subdir_requires_active() {
    let tmp = TempDir::new().unwrap();
    fs::create_dir_all(tmp.path().join(".git")).unwrap();

    // .secretenv/ に members/ と secrets/ だけ → workspace と認識されない
    fs::create_dir_all(tmp.path().join(".secretenv/members")).unwrap();
    fs::create_dir_all(tmp.path().join(".secretenv/secrets")).unwrap();
    let result = detect_workspace_root(tmp.path());
    assert!(result.is_err());

    // .secretenv/members/active/ も追加 → workspace と認識される
    fs::create_dir_all(tmp.path().join(".secretenv/members/active")).unwrap();
    let result = detect_workspace_root(tmp.path());
    assert!(result.is_ok());
    let expected = tmp.path().join(".secretenv").canonicalize().unwrap();
    assert_eq!(result.unwrap().root_path, expected);
}

#[cfg(unix)]
#[test]
fn test_check_workspace_rejects_symlinked_members_active() {
    use std::os::unix::fs::symlink;
    let tmp = TempDir::new().unwrap();
    fs::create_dir_all(tmp.path().join(".git")).unwrap();

    // Build a valid workspace shape, then redirect members/active to an
    // outside directory via a symlink.
    let secretenv_dir = tmp.path().join(".secretenv");
    fs::create_dir_all(secretenv_dir.join("members")).unwrap();
    fs::create_dir_all(secretenv_dir.join("secrets")).unwrap();

    let outside = tmp.path().join("external_active");
    fs::create_dir(&outside).unwrap();
    symlink(&outside, secretenv_dir.join("members").join("active")).unwrap();

    let result = detect_workspace_root(tmp.path());
    assert!(
        result.is_err(),
        "workspace with symlinked members/active must be rejected"
    );
}

#[cfg(unix)]
#[test]
fn test_check_workspace_rejects_symlinked_secrets() {
    use std::os::unix::fs::symlink;
    let tmp = TempDir::new().unwrap();
    fs::create_dir_all(tmp.path().join(".git")).unwrap();

    let secretenv_dir = tmp.path().join(".secretenv");
    fs::create_dir_all(secretenv_dir.join("members/active")).unwrap();

    let outside = tmp.path().join("external_secrets");
    fs::create_dir(&outside).unwrap();
    symlink(&outside, secretenv_dir.join("secrets")).unwrap();

    let result = detect_workspace_root(tmp.path());
    assert!(
        result.is_err(),
        "workspace with symlinked secrets must be rejected"
    );
}
