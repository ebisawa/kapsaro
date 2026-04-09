// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for rewrap command
//!
//! Tests the rewrap command with the simplified RewrapArgs (auto-sync with @all).

use crate::cli::common::{
    cmd, create_temp_ssh_keypair, default_common_options, set_ssh_key_from_temp_dir,
    setup_workspace, ALICE_MEMBER_ID, BOB_MEMBER_ID, TEST_MEMBER_ID,
};
use crate::test_utils::setup_test_workspace;
use predicates::prelude::*;
use secretenv::cli::encrypt;
use secretenv::cli::options::CommonOptions;
use secretenv::cli::rewrap::{self, RewrapArgs};
use secretenv::cli::set;
use secretenv::format::kv::enc::canonical::parse_kv_wrap;
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
fn default_rewrap_args(common_opts: CommonOptions, member_id: &str) -> RewrapArgs {
    RewrapArgs {
        common: common_opts,
        member_id: Some(member_id.to_string()),
        rotate_key: false,
        clear_disclosure_history: false,
    }
}

/// Create a kv-enc file in the workspace using the set command.
///
/// `entries` は `&[("KEY", "VALUE")]` 形式。
fn create_kv_file(
    workspace_dir: &Path,
    common_opts: CommonOptions,
    member_id: &str,
    name: &str,
    entries: &[(&str, &str)],
) -> PathBuf {
    for (key, value) in entries {
        let set_args = set::SetArgs {
            common: common_opts.clone(),

            member_id: Some(member_id.to_string()),
            name: Some(name.to_string()),
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

/// Parse the rids from a kv-enc .kv file's WRAP line.
fn get_kv_rids(kv_path: &Path) -> Vec<String> {
    let content = fs::read_to_string(kv_path).unwrap();
    let (_, _, wrap_data) = parse_kv_wrap(&content).unwrap();
    wrap_data.wrap.iter().map(|w| w.rid.clone()).collect()
}

/// Get the removed_recipients rids from a kv-enc file.
fn get_kv_removed_rids(kv_path: &Path) -> Vec<String> {
    let content = fs::read_to_string(kv_path).unwrap();
    let (_, _, wrap_data) = parse_kv_wrap(&content).unwrap();
    wrap_data
        .removed_recipients
        .unwrap_or_default()
        .iter()
        .map(|r| r.rid.clone())
        .collect()
}
