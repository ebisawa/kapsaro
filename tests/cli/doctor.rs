// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::cli::common::{cmd, setup_workspace, TEST_MEMBER_HANDLE};
use kapsaro_core::cli_api::test_support::storage::keystore::active::load_active_kid;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_doctor_missing_trust_store_warns_but_exits_success() {
    let (workspace_dir, home_dir, _ssh_temp, _ssh_priv) = setup_workspace();

    cmd()
        .arg("doctor")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--home")
        .arg(home_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .assert()
        .success()
        .stdout(predicate::str::contains("Status: WARN"))
        .stdout(predicate::str::contains("kapsaro member verify --approve"));
}

#[test]
fn test_doctor_debug_logs_local_state_without_password_env_name() {
    let (workspace_dir, home_dir, _ssh_temp, _ssh_priv) = setup_workspace();

    cmd()
        .arg("doctor")
        .arg("--debug")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--home")
        .arg(home_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .env("RUST_LOG", "warn")
        .assert()
        .success()
        .stdout(predicate::str::contains("[DOCTOR] local state: start"))
        .stdout(predicate::str::contains(
            "[DOCTOR] local state: inspect active key",
        ))
        .stdout(predicate::str::contains("KAPSARO_KEY_PASSWORD").not());
}

#[test]
fn test_doctor_json_missing_trust_store_warns_but_exits_success() {
    let (workspace_dir, home_dir, _ssh_temp, _ssh_priv) = setup_workspace();

    let output = cmd()
        .arg("doctor")
        .arg("--json")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--home")
        .arg(home_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["status"], "warn");
    assert_eq!(value["exit_code"], 0);
    assert!(value["summary"]["warn"].as_u64().unwrap() > 0);
    assert!(value["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|check| { check["id"] == "trust_store.present" && check["next_action"].is_string() }));
}

#[test]
fn test_doctor_incomplete_workspace_fails() {
    let workspace = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    fs::create_dir_all(workspace.path().join("members/active")).unwrap();

    cmd()
        .arg("doctor")
        .arg("--workspace")
        .arg(workspace.path())
        .arg("--home")
        .arg(home.path())
        .arg("--member-handle")
        .arg("alice@example.com")
        .arg("--verbose")
        .assert()
        .failure()
        .stdout(predicate::str::contains("Status: FAIL"))
        .stdout(predicate::str::contains("workspace.structure"));
}

#[test]
fn test_doctor_json_incomplete_workspace_fails_with_json() {
    let workspace = TempDir::new().unwrap();
    let home = TempDir::new().unwrap();
    fs::create_dir_all(workspace.path().join("members/active")).unwrap();

    let output = cmd()
        .arg("doctor")
        .arg("--json")
        .arg("--workspace")
        .arg(workspace.path())
        .arg("--home")
        .arg(home.path())
        .arg("--member-handle")
        .arg("alice@example.com")
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["status"], "fail");
    assert_eq!(value["exit_code"], 1);
    assert!(value["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|check| { check["id"] == "workspace.structure" && check["status"] == "fail" }));
}

/// Local state entries other users can reach are reported one finding per path,
/// so the operator sees every entry to repair and the diagnosis still finishes.
///
/// The exposed entry here is the public half. The private half is the one entry
/// a read refuses outright, which the key command tests pin, and a diagnosis run
/// against it reports a key that cannot be loaded rather than the warnings this
/// test is about.
#[cfg(unix)]
#[test]
fn test_doctor_reports_each_insecure_local_state_entry_as_a_warning() {
    use std::os::unix::fs::PermissionsExt;

    let (workspace_dir, home_dir, _ssh_temp, _ssh_priv) = setup_workspace();
    let keystore_root = home_dir.path().join("keys");
    let active_kid = load_active_kid(TEST_MEMBER_HANDLE, &keystore_root)
        .unwrap()
        .unwrap();
    let public_path = keystore_root
        .join(TEST_MEMBER_HANDLE)
        .join(active_kid)
        .join("public.json");
    fs::set_permissions(&public_path, fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(home_dir.path(), fs::Permissions::from_mode(0o755)).unwrap();

    let output = cmd()
        .arg("doctor")
        .arg("--json")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--home")
        .arg(home_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let findings: Vec<_> = value["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|check| check["id"] == "local_state.permissions")
        .collect();

    assert_eq!(value["status"], "warn");
    assert_eq!(value["exit_code"], 0);
    assert_eq!(findings.len(), 2, "{findings:#?}");
    assert!(findings.iter().all(|check| {
        check["status"] == "warn"
            && check["category"] == "local_state"
            && check["rule"] == "W_LOCAL_STATE_PERMISSIONS"
            && check["message"] == "Local state entry is reachable by other users"
            && check["next_action"] == "restrict local state permissions to owner only"
    }));
    assert!(findings
        .iter()
        .any(|check| { check["subject"] == home_dir.path().display().to_string() }));
    assert!(findings
        .iter()
        .any(|check| { check["subject"] == public_path.display().to_string() }));
}

/// The permissions the command names as findings stay out of the warning
/// stream, so each one is reported exactly once.
#[cfg(unix)]
#[test]
fn test_doctor_keeps_the_permission_findings_out_of_stderr() {
    use std::os::unix::fs::PermissionsExt;

    let (workspace_dir, home_dir, _ssh_temp, _ssh_priv) = setup_workspace();
    fs::set_permissions(
        home_dir.path().join("keys"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();

    cmd()
        .arg("doctor")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--home")
        .arg(home_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--verbose")
        .assert()
        .code(0)
        .stdout(predicate::str::contains("local_state.permissions"))
        .stderr(predicate::str::is_empty());
}

/// A local state root selected through a symlink is a supported setup, so the
/// report is clean and names the path the operator gave.
#[cfg(unix)]
#[test]
fn test_doctor_diagnoses_a_symlinked_home() {
    use std::os::unix::fs::symlink;

    let (workspace_dir, home_dir, _ssh_temp, _ssh_priv) = setup_workspace();
    let links = TempDir::new().unwrap();
    let selected_home = links.path().join("selected-home");
    symlink(home_dir.path(), &selected_home).unwrap();

    cmd()
        .arg("doctor")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--home")
        .arg(&selected_home)
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .arg("--verbose")
        .assert()
        .code(0)
        .stdout(predicate::str::contains(
            selected_home.display().to_string(),
        ))
        .stderr(predicate::str::is_empty());
}

/// A private key others can reach is refused rather than handed out, so every
/// command stops until it is repaired and the diagnosis says so in its exit
/// code. The key is present and intact, so the repair named is the one `chmod`
/// that fixes it rather than a restore from backup.
///
/// The exposure carries a rule of its own. A link standing where the key
/// document belongs fails under the unsafe-path rule and keeps the restore
/// route, which the test below pins.
#[cfg(unix)]
#[test]
fn test_doctor_fails_on_an_exposed_private_key_and_names_the_chmod() {
    use std::os::unix::fs::PermissionsExt;

    let (workspace_dir, home_dir, _ssh_temp, _ssh_priv) = setup_workspace();
    let keystore_root = home_dir.path().join("keys");
    let active_kid = load_active_kid(TEST_MEMBER_HANDLE, &keystore_root)
        .unwrap()
        .unwrap();
    let private_path = keystore_root
        .join(TEST_MEMBER_HANDLE)
        .join(active_kid)
        .join("private.json");
    fs::set_permissions(&private_path, fs::Permissions::from_mode(0o644)).unwrap();

    let output = cmd()
        .arg("doctor")
        .arg("--json")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--home")
        .arg(home_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["status"], "fail");
    assert_eq!(value["exit_code"], 1);
    let check = value["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["id"] == "keystore.private_key")
        .unwrap_or_else(|| panic!("{value:#}"));

    assert_eq!(check["status"], "fail");
    assert_eq!(check["rule"], "E_LOCAL_STATE_PRIVATE_KEY_EXPOSED");
    assert_eq!(
        check["message"],
        "Active private key is reachable by other users and was not read"
    );
    assert!(
        check["next_action"]
            .as_str()
            .is_some_and(|action| action.contains("chmod 0600")),
        "{check:#}"
    );
    assert!(
        check["subject"]
            .as_str()
            .is_some_and(|subject| subject.ends_with("private.json")),
        "{check:#}"
    );
}

#[cfg(unix)]
#[test]
fn test_doctor_json_preserves_unsafe_rule_for_active_private_key() {
    use std::os::unix::fs::symlink;

    let (workspace_dir, home_dir, _ssh_temp, _ssh_priv) = setup_workspace();
    let keystore_root = home_dir.path().join("keys");
    let active_kid = load_active_kid(TEST_MEMBER_HANDLE, &keystore_root)
        .unwrap()
        .unwrap();
    let private_path = keystore_root
        .join(TEST_MEMBER_HANDLE)
        .join(active_kid)
        .join("private.json");
    let outside = home_dir.path().join("outside-private.json");
    fs::copy(&private_path, &outside).unwrap();
    fs::remove_file(&private_path).unwrap();
    symlink(&outside, &private_path).unwrap();

    let output = cmd()
        .arg("doctor")
        .arg("--json")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--home")
        .arg(home_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert!(value["checks"].as_array().unwrap().iter().any(|check| {
        check["id"] == "keystore.private_key"
            && check["status"] == "fail"
            && check["rule"] == "E_LOCAL_STATE_PATH_UNSAFE"
    }));
}

/// A local state root under a directory another user can write is named as a
/// finding of its own, and the diagnosis says which directory to repair.
#[cfg(unix)]
#[test]
fn test_doctor_reports_a_group_writable_home_ancestor() {
    use std::os::unix::fs::PermissionsExt;

    let (workspace_dir, home_dir, _ssh_temp, _ssh_priv) = setup_workspace();
    let shared = home_dir.path().join("shared");
    fs::create_dir(&shared).unwrap();
    let nested_home = shared.join("home");
    fs::create_dir(&nested_home).unwrap();
    fs::set_permissions(&nested_home, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();

    let output = cmd()
        .arg("doctor")
        .arg("--json")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--home")
        .arg(&nested_home)
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["status"], "warn");
    assert!(value["checks"].as_array().unwrap().iter().any(|check| {
        check["id"] == "local_state.permissions"
            && check["status"] == "warn"
            && check["rule"] == "W_LOCAL_STATE_PERMISSIONS"
            && check["message"] == "Local state ancestor directory is writable by other users"
            && check["next_action"]
                == "remove group and other write access from the local state ancestor directory"
            && check["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("chmod go-w"))
    }));
}

/// Selecting the local state root through a symlink is a supported layout, so
/// the chain that has to be safe is the one leading to the directory the link
/// resolves to. A writable directory there lets another user swap the tree the
/// next run opens, whatever the link is named.
#[cfg(unix)]
#[test]
fn test_doctor_reports_a_group_writable_ancestor_behind_a_symlinked_home() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let (workspace_dir, home_dir, _ssh_temp, _ssh_priv) = setup_workspace();
    let shared = home_dir.path().join("shared");
    fs::create_dir(&shared).unwrap();
    let real_home = shared.join("real-home");
    fs::create_dir(&real_home).unwrap();
    fs::set_permissions(&real_home, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
    let links = TempDir::new().unwrap();
    let selected_home = links.path().join("selected-home");
    symlink(&real_home, &selected_home).unwrap();

    let output = cmd()
        .arg("doctor")
        .arg("--json")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--home")
        .arg(&selected_home)
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let resolved_shared = fs::canonicalize(&shared).unwrap().display().to_string();
    assert!(
        value["checks"].as_array().unwrap().iter().any(|check| {
            check["id"] == "local_state.permissions"
                && check["status"] == "warn"
                && check["message"] == "Local state ancestor directory is writable by other users"
                && check["subject"] == resolved_shared
        }),
        "{value:#}"
    );
}

/// A root that never opened leaves the tree uninspected, so the check reports
/// that it did not run instead of passing an unscanned tree as owner-only.
#[cfg(unix)]
#[test]
fn test_doctor_skips_the_permission_check_when_the_home_is_absent() {
    let (workspace_dir, home_dir, _ssh_temp, _ssh_priv) = setup_workspace();
    let absent_home = home_dir.path().join("absent-home");

    let output = cmd()
        .arg("doctor")
        .arg("--json")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--home")
        .arg(&absent_home)
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .assert()
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert!(
        value["checks"].as_array().unwrap().iter().any(|check| {
            check["id"] == "local_state.permissions"
                && check["status"] == "skip"
                && check["message"] == "Local state permissions were not checked"
        }),
        "{value:#}"
    );
}

/// A finding has to name a path the operator can act on. An ancestor that
/// happens to be the working directory would otherwise render as nothing.
#[cfg(unix)]
#[test]
fn test_doctor_names_an_ancestor_that_equals_the_working_directory() {
    use std::os::unix::fs::PermissionsExt;

    let (workspace_dir, home_dir, _ssh_temp, _ssh_priv) = setup_workspace();
    let shared = home_dir.path().join("shared");
    fs::create_dir(&shared).unwrap();
    let nested_home = shared.join("home");
    fs::create_dir(&nested_home).unwrap();
    fs::set_permissions(&nested_home, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();

    let output = cmd()
        .current_dir(&shared)
        .arg("doctor")
        .arg("--json")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--home")
        .arg("home")
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let ancestor = value["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| {
            check["id"] == "local_state.permissions"
                && check["message"] == "Local state ancestor directory is writable by other users"
        })
        .unwrap_or_else(|| panic!("{value:#}"));
    assert_eq!(
        ancestor["subject"],
        fs::canonicalize(&shared).unwrap().display().to_string()
    );
}

/// Entry names come from the filesystem, so one of them can hold the separator
/// the reported line is read with. The machine-readable output keeps each name
/// on its own, and nothing there invites splitting a line back apart.
#[test]
fn test_doctor_json_lists_ignored_keystore_entries_as_separate_names() {
    let (workspace_dir, home_dir, _ssh_temp, _ssh_priv) = setup_workspace();
    let keystore_root = home_dir.path().join("keys");
    fs::write(keystore_root.join("first, second"), b"").unwrap();
    fs::write(keystore_root.join("third"), b"").unwrap();

    let output = cmd()
        .arg("doctor")
        .arg("--json")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .arg("--home")
        .arg(home_dir.path())
        .arg("--member-handle")
        .arg(TEST_MEMBER_HANDLE)
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let check = value["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["message"] == "Unexpected entries in the keystore directory")
        .unwrap_or_else(|| panic!("{value:#}"));
    let mut names = check["reason_entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        vec!["first, second".to_string(), "third".to_string()]
    );
    assert!(check["reason"].is_null(), "{check:#}");
}
