// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests that CLI write sessions retain one opened workspace identity.
//! Covers recipient resolution and repeated KV plans after the path is replaced.

use std::fs;
use std::path::{Path, PathBuf};

use kapsaro_core::api::file::encrypt::{
    execute_encrypt_file_command_with_recipient_set_confirmation, resolve_encrypt_file_command,
};
use kapsaro_core::api::kv::mutation::{
    reevaluate_mutation_write_plan_after_review, resolve_mutation_write_plan,
    set_kv_command_with_recipient_set_confirmation,
};
use kapsaro_core::api::kv::KvInputEntry;
use kapsaro_core::api::secret::SecretString;
use kapsaro_core::api::workspace::WorkspaceWriteDirectories;
use kapsaro_test_support::fixture::setup_test_workspace_from_fixtures;

use crate::cli::common::context::CliContext;
use crate::cli::options::CommonOptions;
use crate::test_utils::EnvGuard;

use super::{resolve_cli_write_session, set_pre_signing_key_load_hook, CliWriteSession};

const ALICE_MEMBER_HANDLE: &str = "alice@example.com";

struct SwappedWorkspaceFixture {
    _env: EnvGuard,
    _home: tempfile::TempDir,
    original_workspace: PathBuf,
    replacement_workspace: PathBuf,
    session: CliWriteSession,
}

fn setup_swapped_workspace_session() -> SwappedWorkspaceFixture {
    let env = EnvGuard::new(&["KAPSARO_MEMBER_HANDLE", "KAPSARO_STRICT_KEY_CHECKING"]);
    std::env::remove_var("KAPSARO_MEMBER_HANDLE");
    std::env::remove_var("KAPSARO_STRICT_KEY_CHECKING");
    let (home, workspace_path) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let original_workspace = home.path().join("workspace-original");
    let replacement_source = home.path().join("workspace-replacement");
    ensure_empty_workspace(&replacement_source);

    let options = CommonOptions {
        home: Some(home.path().to_path_buf()),
        identity: Some(home.path().join(".ssh/test_ed25519")),
        ssh_keygen: true,
        workspace: Some(workspace_path.clone()),
        ..CommonOptions::default()
    };
    let context = CliContext::resolve(&options).unwrap();
    let directories = WorkspaceWriteDirectories::open(&workspace_path).unwrap();

    let original_for_swap = original_workspace.clone();
    let replacement_for_swap = replacement_source.clone();
    let workspace_for_swap = workspace_path.clone();
    set_pre_signing_key_load_hook(move || {
        fs::rename(&workspace_for_swap, &original_for_swap).unwrap();
        fs::rename(&replacement_for_swap, &workspace_for_swap).unwrap();
    });

    let session = resolve_cli_write_session(
        &context,
        directories,
        Some(ALICE_MEMBER_HANDLE.to_string()),
        false,
    )
    .unwrap();

    SwappedWorkspaceFixture {
        _env: env,
        _home: home,
        original_workspace,
        replacement_workspace: workspace_path,
        session,
    }
}

fn ensure_empty_workspace(path: &Path) {
    fs::create_dir_all(path.join("members/active")).unwrap();
    fs::create_dir_all(path.join("members/incoming")).unwrap();
    fs::create_dir_all(path.join("secrets")).unwrap();
}

#[test]
fn test_cli_write_session_encrypt_uses_opened_workspace_after_path_replacement() {
    let fixture = setup_swapped_workspace_session();

    let command = resolve_encrypt_file_command(
        fixture.session.directories(),
        fixture.session.trust(),
        fixture.session.options(),
        b"secret".to_vec(),
    )
    .unwrap();
    let encrypted =
        execute_encrypt_file_command_with_recipient_set_confirmation(&command, |_, _| Ok(true))
            .unwrap();
    let document: serde_json::Value = serde_json::from_str(&encrypted).unwrap();
    let recipient_handles = document["protected"]["wrap"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["rh"].as_str().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(recipient_handles, vec![ALICE_MEMBER_HANDLE]);
    assert!(fixture
        .replacement_workspace
        .join("members/active")
        .exists());
}

#[test]
fn test_cli_write_session_reuses_opened_workspace_for_repeated_kv_plans() {
    let fixture = setup_swapped_workspace_session();

    for (key, value) in [("FIRST", "one"), ("SECOND", "two")] {
        let plan = resolve_mutation_write_plan(
            fixture.session.directories(),
            fixture.session.trust(),
            fixture.session.options(),
            None,
            true,
        )
        .unwrap();
        let plan = reevaluate_mutation_write_plan_after_review(plan).unwrap();
        set_kv_command_with_recipient_set_confirmation(
            &plan,
            vec![KvInputEntry::new(
                key.to_string(),
                SecretString::new(value.to_string()),
            )],
            |_, _| Ok(true),
        )
        .unwrap();
    }

    assert!(fixture
        .original_workspace
        .join("secrets/default.kvenc")
        .is_file());
    assert!(!fixture
        .replacement_workspace
        .join("secrets/default.kvenc")
        .exists());
}
