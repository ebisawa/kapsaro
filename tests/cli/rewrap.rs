// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for rewrap command
//!
//! Tests the rewrap command with the simplified RewrapArgs (auto-sync with @all).

use crate::cli::common::{
    append_common_command_args, cmd, default_common_options, encrypt_file_with_member_set_review,
    generate_temp_ssh_keypair, set_ssh_key_from_temp_dir, set_value_with_member_set_review,
    setup_workspace, setup_workspace_with_kv_entries, tamper_kv_signature, CommonOptions,
    ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE, TEST_MEMBER_HANDLE,
};
use kapsaro_test_support::fixture::setup_test_workspace;
use predicates::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use temp_env::with_vars;

#[path = "rewrap/membership.rs"]
mod membership;
#[path = "rewrap/operations.rs"]
mod operations;
#[path = "rewrap/preconditions.rs"]
mod preconditions;
#[path = "rewrap/roundtrip.rs"]
mod roundtrip;

fn run_rewrap_with_member_set_review(common_opts: &CommonOptions, member_handle: &str) {
    run_rewrap_with_member_set_review_args(common_opts, member_handle, &[]);
}

fn run_rewrap_with_member_set_review_args(
    common_opts: &CommonOptions,
    member_handle: &str,
    extra_args: &[&str],
) {
    let mut command = crate::cli::common::kapsaro_std_cmd();
    command
        .arg("rewrap")
        .arg("--member-handle")
        .arg(member_handle);
    append_common_command_args(&mut command, common_opts);
    for arg in extra_args {
        command.arg(arg);
    }
    crate::cli::common::assert_member_set_review_success(&mut command);
}

fn run_rewrap_command(
    common_opts: &CommonOptions,
    member_handle: &str,
    extra_args: &[&str],
) -> std::process::Output {
    let mut command = crate::cli::common::kapsaro_std_cmd();
    command
        .arg("rewrap")
        .arg("--member-handle")
        .arg(member_handle);
    append_common_command_args(&mut command, common_opts);
    for arg in extra_args {
        command.arg(arg);
    }
    command.output().unwrap()
}

/// Create a kv-enc file in the workspace using the set command.
///
/// `entries` は `&[("KEY", "VALUE")]` 形式。
fn save_kv_file(
    workspace_dir: &Path,
    common_opts: CommonOptions,
    member_handle: &str,
    name: &str,
    entries: &[(&str, &str)],
) -> PathBuf {
    for (index, (key, value)) in entries.iter().enumerate() {
        if index == 0 {
            set_value_with_member_set_review(
                common_opts
                    .workspace
                    .as_deref()
                    .expect("test common options must include workspace"),
                common_opts
                    .home
                    .as_deref()
                    .expect("test common options must include home"),
                common_opts
                    .identity
                    .as_deref()
                    .expect("test common options must include identity"),
                key,
                value,
                Some(member_handle),
                Some(name),
            );
            continue;
        }
        set_value_with_member_set_review(
            common_opts
                .workspace
                .as_deref()
                .expect("test common options must include workspace"),
            common_opts
                .home
                .as_deref()
                .expect("test common options must include home"),
            common_opts
                .identity
                .as_deref()
                .expect("test common options must include identity"),
            key,
            value,
            Some(member_handle),
            Some(name),
        );
    }
    workspace_dir
        .join("secrets")
        .join(format!("{}.kvenc", name))
}
