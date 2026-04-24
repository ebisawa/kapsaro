// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `init` command.

use crate::cli::common::generate_temp_ssh_keypair;
use std::path::PathBuf;
use tempfile::TempDir;

#[path = "init/key_generation.rs"]
mod key_generation;
#[path = "init/member_handle.rs"]
mod member_handle;
#[path = "init/output.rs"]
mod output;
#[path = "init/registration.rs"]
mod registration;
#[path = "init/workspace.rs"]
mod workspace;

fn setup_init_env() -> (TempDir, TempDir, TempDir, PathBuf) {
    let workspace_dir = TempDir::new().unwrap();
    let home_dir = TempDir::new().unwrap();
    let (ssh_temp, ssh_priv, _ssh_pub, _ssh_pub_content) = generate_temp_ssh_keypair();
    (workspace_dir, home_dir, ssh_temp, ssh_priv)
}
