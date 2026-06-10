// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

// Workspace setup helpers and CommonOptions for CLI integration tests.
// Provides initialised test workspaces and shared command-argument builders.

use super::execution::cmd;
use super::review::set_value_with_member_set_review;
use kapsaro_test_support::constants::TEST_MEMBER_HANDLE;
use kapsaro_test_support::fixture::generate_temp_ssh_keypair_in_dir;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Command as StdCommand;
use tempfile::TempDir;

/// Options shared across CLI integration test commands.
#[derive(Clone, Debug, Default)]
pub struct CommonOptions {
    pub home: Option<PathBuf>,
    pub identity: Option<PathBuf>,
    pub json: bool,
    pub quiet: bool,
    pub workspace: Option<PathBuf>,
}

/// Creates a `CommonOptions` with all fields at their defaults.
pub fn default_common_options() -> CommonOptions {
    CommonOptions {
        home: None,
        workspace: None,
        identity: None,
        json: false,
        quiet: false,
    }
}

/// Sets the SSH identity in `common_opts` to the test key inside `temp_dir`.
pub fn set_ssh_key_from_temp_dir(common_opts: &mut CommonOptions, temp_dir: &TempDir) {
    let ssh_key_path = temp_dir.path().join(".ssh").join("test_ed25519");
    common_opts.identity = Some(ssh_key_path);
}

/// Appends workspace, json, quiet, home, and identity args/envs to a command.
#[cfg(unix)]
pub fn append_common_command_args(command: &mut StdCommand, common_opts: &CommonOptions) {
    if let Some(workspace) = &common_opts.workspace {
        command.arg("--workspace").arg(workspace);
    }
    if common_opts.json {
        command.arg("--json");
    }
    if common_opts.quiet {
        command.arg("--quiet");
    }
    if let Some(home) = &common_opts.home {
        command.env("KAPSARO_HOME", home);
    }
    if let Some(identity) = &common_opts.identity {
        command.env("KAPSARO_SSH_IDENTITY", identity);
    }
}

/// Creates a temporary workspace initialised with a test member.
///
/// Returns (workspace_dir, home_dir, ssh_temp_dir, ssh_priv_path).
pub fn setup_workspace() -> (TempDir, TempDir, TempDir, PathBuf) {
    let workspace_dir = TempDir::new().unwrap();
    let home_dir = make_secret_home();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();

    std::fs::create_dir_all(workspace_dir.path().join("members")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();

    let output = cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .env("KAPSARO_HOME", home_dir.path())
        .env("KAPSARO_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .output()
        .unwrap();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("failed to initialize test workspace: {}", stderr.trim());
    }

    (workspace_dir, home_dir, ssh_temp, ssh_priv)
}

/// Creates an initialised workspace pre-populated with the given KV entries.
#[cfg(unix)]
pub fn setup_workspace_with_kv_entries(
    entries: &[(&str, &str)],
) -> (TempDir, TempDir, TempDir, PathBuf) {
    let (workspace_dir, home_dir, ssh_temp, ssh_priv) = setup_workspace();
    for (key, value) in entries {
        set_value_with_member_set_review(
            workspace_dir.path(),
            home_dir.path(),
            &ssh_priv,
            key,
            value,
            None,
            None,
        );
    }
    (workspace_dir, home_dir, ssh_temp, ssh_priv)
}

/// Creates a temporary SSH Ed25519 keypair for testing.
///
/// Returns (temp_dir, private_key_path, public_key_path, public_key_content).
pub fn generate_temp_ssh_keypair() -> (TempDir, PathBuf, PathBuf, String) {
    let temp_dir = TempDir::new().unwrap();
    let (private_key_path, public_key_path, public_key_content) =
        generate_temp_ssh_keypair_in_dir(&temp_dir);

    (
        temp_dir,
        private_key_path,
        public_key_path,
        public_key_content,
    )
}

/// Creates a temporary directory with restricted permissions suitable for a secret home.
pub fn make_secret_home() -> TempDir {
    let home_dir = TempDir::new().unwrap();
    set_secret_home_permissions(&home_dir);
    home_dir
}

#[cfg(unix)]
fn set_secret_home_permissions(home_dir: &TempDir) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(home_dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(not(unix))]
fn set_secret_home_permissions(_home_dir: &TempDir) {}

/// Copies a directory tree from `source` to `destination` recursively.
pub fn copy_dir_all(source: &Path, destination: &Path) {
    std::fs::create_dir_all(destination).unwrap();
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let file_type = entry.file_type().unwrap();
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_all(&source_path, &destination_path);
        } else {
            std::fs::copy(&source_path, &destination_path).unwrap();
        }
    }
}
