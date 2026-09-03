// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the KV command session binding.

use crate::app_test_utils::{build_test_signing_command_options, resolve_test_write_execution};
use crate::service::kv::session::KvCommandSession;
use crate::service::workspace::WorkspaceWriteCapabilities;
use crate::support::fs::relative::DirectoryFd;
use crate::test_support::storage::keystore::active::set_active_kid;
use crate::test_support::storage::keystore::storage::list_kids;
use crate::test_utils::{setup_test_workspace_from_fixtures, with_temp_cwd, EnvGuard};

const ALICE_MEMBER_HANDLE: &str = "alice@example.com";

fn activate_fixture_key(home: &std::path::Path) {
    let keystore_root = home.join("keys");
    let kid = list_kids(&keystore_root, ALICE_MEMBER_HANDLE)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    set_active_kid(ALICE_MEMBER_HANDLE, &kid, &keystore_root).unwrap();
}

/// The write replaces the target through the secrets directory the execution
/// opened, so the file the session binds has to live in that very directory.
/// Comparing the directory identities rather than the paths is what makes a
/// second resolution of the workspace visible here.
#[cfg(unix)]
#[test]
fn test_write_target_lives_in_the_secrets_directory_the_execution_fixed() {
    use std::os::unix::fs::MetadataExt;

    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_execution(&options, ALICE_MEMBER_HANDLE);
        let capabilities =
            WorkspaceWriteCapabilities::new(&execution.directories, &execution.trust);
        let session = KvCommandSession::bind_write(&capabilities, None).unwrap();

        let bound_dir = std::fs::metadata(session.target.file_path.parent().unwrap()).unwrap();
        let fixed_dir = capabilities.secrets().file().metadata().unwrap();
        assert_eq!(
            (bound_dir.dev(), bound_dir.ino()),
            (fixed_dir.dev(), fixed_dir.ino()),
            "the bound target must sit in the secrets directory the write runs against"
        );
    });
}

/// An explicit name selects the file inside that same fixed directory.
#[test]
fn test_write_target_uses_the_named_file_in_the_fixed_workspace() {
    let _guard = EnvGuard::new(&["KAPSARO_STRICT_KEY_CHECKING"]);
    let (temp_dir, workspace_dir) = setup_test_workspace_from_fixtures(&[ALICE_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    activate_fixture_key(temp_dir.path());

    with_temp_cwd(temp_dir.path(), || {
        let execution = resolve_test_write_execution(&options, ALICE_MEMBER_HANDLE);
        let capabilities =
            WorkspaceWriteCapabilities::new(&execution.directories, &execution.trust);
        let session = KvCommandSession::bind_write(&capabilities, Some("staging")).unwrap();

        assert_eq!(
            session.target.file_path.file_name().unwrap(),
            "staging.kvenc"
        );
        assert_eq!(
            session
                .target
                .file_path
                .parent()
                .unwrap()
                .canonicalize()
                .unwrap(),
            workspace_dir.join("secrets").canonicalize().unwrap()
        );
    });
}
