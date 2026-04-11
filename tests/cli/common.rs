// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Common helpers for CLI integration tests
//!
//! This module provides shared helper functions and constants used across
//! CLI integration tests to reduce code duplication and improve maintainability.

use crate::test_utils::create_temp_ssh_keypair_in_dir;
pub use crate::test_utils::{
    ALICE_MEMBER_ID, BOB_MEMBER_ID, CAROL_MEMBER_ID, DAVE_MEMBER_ID, EVE_MEMBER_ID,
    FRANK_MEMBER_ID, TEST_MEMBER_ID,
};
use assert_cmd::{cargo, Command};
use secretenv::cli::options::CommonOptions;
use std::path::PathBuf;
use tempfile::TempDir;

// ============================================================================
// Test Binary Helper
// ============================================================================

/// Helper to get the secretenv test binary command.
///
/// Sets `SECRETENV_SSH_SIGNING_METHOD=ssh-keygen` for CLI integration tests.
pub fn cmd() -> Command {
    let mut c = cargo::cargo_bin_cmd!("secretenv");
    c.env("SECRETENV_SSH_SIGNING_METHOD", "ssh-keygen");
    c
}

// ============================================================================
// Test Constants
// ============================================================================

// ============================================================================
// Common Helper Functions
// ============================================================================

/// Helper to create default CommonOptions for testing.
///
/// Uses `ssh_keygen: true` so tests work in CI environments where
/// `SSH_AUTH_SOCK` is set but no keys are loaded in the agent.
pub fn default_common_options() -> CommonOptions {
    CommonOptions {
        home: None,
        workspace: None,
        identity: None,
        ssh_agent: false,
        ssh_keygen: true,
        json: false,
        quiet: false,
        verbose: false,
    }
}

/// Helper to set SSH key path in CommonOptions from temp_dir
pub fn set_ssh_key_from_temp_dir(common_opts: &mut CommonOptions, temp_dir: &TempDir) {
    let ssh_key_path = temp_dir.path().join(".ssh").join("test_ed25519");
    common_opts.identity = Some(ssh_key_path);
}

/// Helper to create a workspace with initialized member.
///
/// Returns: (workspace_dir, home_dir, ssh_temp, ssh_priv_path)
pub fn setup_workspace() -> (TempDir, TempDir, TempDir, PathBuf) {
    let workspace_dir = TempDir::new().unwrap();
    let home_dir = TempDir::new().unwrap();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = create_temp_ssh_keypair();

    std::fs::create_dir_all(workspace_dir.path().join("members")).unwrap();
    std::fs::create_dir_all(workspace_dir.path().join("secrets")).unwrap();

    let output = cmd()
        .arg("init")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--member-id")
        .arg(TEST_MEMBER_ID)
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .output()
        .unwrap();

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("failed to initialize test workspace: {}", stderr.trim());
    }

    (workspace_dir, home_dir, ssh_temp, ssh_priv)
}

/// Helper to create a temporary SSH Ed25519 keypair for testing
///
/// Returns: (temp_dir, private_key_path, public_key_path, public_key_content)
pub fn create_temp_ssh_keypair() -> (TempDir, PathBuf, PathBuf, String) {
    let temp_dir = TempDir::new().unwrap();
    let (private_key_path, public_key_path, public_key_content) =
        create_temp_ssh_keypair_in_dir(&temp_dir);

    (
        temp_dir,
        private_key_path,
        public_key_path,
        public_key_content,
    )
}
