// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for rewrap command
//!
//! Tests the rewrap command with the simplified RewrapArgs (auto-sync with @all).

use crate::cli::common::{
    cmd, default_common_options, encrypt_file_with_member_set_review, generate_temp_ssh_keypair,
    set_ssh_key_from_temp_dir, set_value_with_member_set_review, setup_workspace,
    ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE, TEST_MEMBER_HANDLE,
};
use crate::test_utils::setup_test_workspace;
use predicates::prelude::*;
use secretenv::cli::options::CommonOptions;
use secretenv::cli::rewrap::{self, RewrapArgs};
use secretenv::cli::set;
use secretenv_core::cli_api::test_support::wire::kv::enc::canonical::parse_kv_wrap;
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

/// Build a default RewrapArgs for testing.
fn default_rewrap_args(common_opts: CommonOptions, member_handle: &str) -> RewrapArgs {
    RewrapArgs {
        common: common_opts.into(),
        member: secretenv::cli::options::MemberHandleOption {
            member_handle: Some(member_handle.to_string()),
        },
        rotate_key: false,
        clear_disclosure_history: false,
        targets: Vec::new(),
    }
}

fn run_rewrap_with_member_set_review(common_opts: &CommonOptions, member_handle: &str) {
    run_rewrap_with_member_set_review_args(common_opts, member_handle, &[]);
}

fn run_rewrap_with_member_set_review_args(
    common_opts: &CommonOptions,
    member_handle: &str,
    extra_args: &[&str],
) {
    let mut command = crate::cli::common::secretenv_std_cmd();
    command
        .arg("rewrap")
        .arg("--workspace")
        .arg(
            common_opts
                .workspace
                .as_deref()
                .expect("test common options must include workspace"),
        )
        .arg("--member-handle")
        .arg(member_handle)
        .env(
            "SECRETENV_HOME",
            common_opts
                .home
                .as_deref()
                .expect("test common options must include home"),
        )
        .env(
            "SECRETENV_SSH_IDENTITY",
            common_opts
                .identity
                .as_deref()
                .expect("test common options must include identity"),
        );
    for arg in extra_args {
        command.arg(arg);
    }
    crate::cli::common::assert_member_set_review_success(&mut command);
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
        let set_args = set::SetArgs {
            common: common_opts.clone().into(),
            member: secretenv::cli::options::MemberHandleOption {
                member_handle: Some(member_handle.to_string()),
            },
            store: secretenv::cli::options::KvStoreNameOption {
                name: Some(name.to_string()),
            },
            stdin: false,
            key: key.to_string(),
            value: Some(value.to_string()),
        };
        set::run(set_args).unwrap();
    }
    workspace_dir
        .join("secrets")
        .join(format!("{}.kvenc", name))
}

/// Parse the recipient_handles from a kv-enc .kv file's WRAP line.
fn load_kv_recipient_handles(kv_path: &Path) -> Vec<String> {
    let content = fs::read_to_string(kv_path).unwrap();
    let (_, _, wrap_data) = parse_kv_wrap(&content).unwrap();
    wrap_data
        .wrap
        .iter()
        .map(|w| w.recipient_handle.clone())
        .collect()
}

/// Get the removed_recipients recipient_handles from a kv-enc file.
fn load_kv_removed_recipient_handles(kv_path: &Path) -> Vec<String> {
    let content = fs::read_to_string(kv_path).unwrap();
    let (_, _, wrap_data) = parse_kv_wrap(&content).unwrap();
    wrap_data
        .removed_recipients
        .unwrap_or_default()
        .iter()
        .map(|r| r.recipient_handle.clone())
        .collect()
}
