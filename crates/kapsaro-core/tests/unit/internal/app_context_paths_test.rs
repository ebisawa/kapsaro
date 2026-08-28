// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Internal tests for app-layer path resolution.
//! Covers the guidance a command gets when no workspace can be resolved, and
//! that every tree a command works through comes from the root it fixed.

use std::path::Path;

use serial_test::serial;

use crate::app::context::options::{resolve_read_trust_allowances, CommonCommandOptions};
use crate::app::context::paths::{require_workspace, CommandPathResolution};
#[cfg(unix)]
use crate::io::keystore::access::KeystoreAccess;
#[cfg(unix)]
use crate::test_utils::{create_local_state_dir, write_local_state_file};
use crate::test_utils::{local_state_temp_dir, with_temp_cwd, EnvGuard};

const WORKSPACE_ENV_VARS: &[&str] = &["KAPSARO_HOME", "KAPSARO_WORKSPACE"];

/// Every setting and every tree a read command resolves, plus the env overrides
/// that would answer for them before the configuration is ever read.
#[cfg(unix)]
const FIXED_ROOT_ENV_VARS: &[&str] = &[
    "KAPSARO_HOME",
    "KAPSARO_WORKSPACE",
    "KAPSARO_ALLOW_NON_MEMBER",
    "KAPSARO_ALLOW_EXPIRED_KEY",
];

fn build_options(home: &Path) -> CommonCommandOptions {
    CommonCommandOptions::new().with_home(Some(home.to_path_buf()))
}

/// Run `resolve` where nothing configures or reveals a workspace: an empty
/// local state home, no environment override, and a directory outside any
/// repository.
fn message_without_any_workspace(
    resolve: impl FnOnce(&CommonCommandOptions, &str) -> crate::Error,
) -> String {
    let _env = EnvGuard::new(WORKSPACE_ENV_VARS);
    let home = local_state_temp_dir();
    std::env::set_var("KAPSARO_HOME", home.path());
    std::env::remove_var("KAPSARO_WORKSPACE");
    let options = build_options(home.path());
    let unrelated_dir = tempfile::tempdir().unwrap();

    with_temp_cwd(unrelated_dir.path(), || {
        resolve(&options, "sharing a secret").to_string()
    })
}

fn assert_names_the_purpose_and_every_option(message: &str) {
    assert!(
        message.contains("sharing a secret requires a Kapsaro workspace"),
        "{message}"
    );
    assert!(message.contains("kapsaro init"), "{message}");
    assert!(message.contains(".kapsaro/"), "{message}");
    assert!(message.contains("--workspace <path>"), "{message}");
}

#[test]
#[serial]
fn test_require_workspace_explains_the_purpose_and_every_way_to_supply_a_workspace() {
    let message = message_without_any_workspace(|options, purpose| {
        require_workspace(options, purpose).unwrap_err()
    });

    assert_names_the_purpose_and_every_option(&message);
}

#[test]
#[serial]
fn test_path_resolution_require_workspace_explains_the_purpose_and_every_way_to_supply_a_workspace()
{
    let message = message_without_any_workspace(|options, purpose| {
        CommandPathResolution::require_workspace(options, purpose).unwrap_err()
    });

    assert_names_the_purpose_and_every_option(&message);
}

/// One local state root, configured to relax the non-member rule and to name
/// its own workspace.
#[cfg(unix)]
fn write_local_state_root(root: &Path, allow_non_member: &str, workspace: &Path) {
    create_local_state_dir(root);
    write_local_state_file(
        &root.join("config.toml"),
        format!(
            "allow_non_member = \"{}\"\nworkspace = \"{}\"\n",
            allow_non_member,
            workspace.display()
        ),
    );
}

/// A directory of the shape workspace detection accepts.
#[cfg(unix)]
fn create_workspace(path: &Path) {
    std::fs::create_dir_all(path.join("members").join("active")).unwrap();
    std::fs::create_dir_all(path.join("secrets")).unwrap();
}

/// The allowances a command settles first and the trees it works through
/// afterwards must all come from the root it fixed when it started.
///
/// A root repointed in between would otherwise carry the relaxed setting of the
/// root that answered the allowance question into an evaluation of another
/// root's workspace, keystore and trust store.
#[cfg(unix)]
#[test]
#[serial]
fn test_allowances_and_trees_resolve_from_the_root_fixed_at_the_start() {
    use std::os::unix::fs::symlink;

    let _env = EnvGuard::new(FIXED_ROOT_ENV_VARS);
    for name in FIXED_ROOT_ENV_VARS {
        std::env::remove_var(name);
    }

    let temp = local_state_temp_dir();
    let relaxed_workspace = temp.path().join("relaxed-workspace");
    let strict_workspace = temp.path().join("strict-workspace");
    create_workspace(&relaxed_workspace);
    create_workspace(&strict_workspace);

    let relaxed = temp.path().join("relaxed");
    let strict = temp.path().join("strict");
    write_local_state_root(&relaxed, "yes", &relaxed_workspace);
    write_local_state_root(&strict, "no", &strict_workspace);
    create_local_state_dir(&relaxed.join("keys"));

    let selected = temp.path().join("selected");
    symlink(&relaxed, &selected).unwrap();
    let options = build_options(&selected);

    let allowances = resolve_read_trust_allowances(None, None, &options).unwrap();
    assert!(allowances.allow_non_member);

    std::fs::remove_file(&selected).unwrap();
    symlink(&strict, &selected).unwrap();

    let paths = CommandPathResolution::load(&options).unwrap();
    assert_eq!(
        paths.workspace_root.as_ref().unwrap().root_path,
        relaxed_workspace.canonicalize().unwrap()
    );
    assert!(
        KeystoreAccess::open_optional_from_anchored_home(paths.home().unwrap())
            .unwrap()
            .is_some(),
        "the keystore is reached through the root the command fixed"
    );
}
