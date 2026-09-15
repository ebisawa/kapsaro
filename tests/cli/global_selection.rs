// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Checks global workspace option parsing and input error presentation.

use crate::cli::common::cmd;
use predicates::prelude::*;

#[cfg(unix)]
struct GlobalFixture {
    home: tempfile::TempDir,
    local: tempfile::TempDir,
}

#[cfg(unix)]
impl GlobalFixture {
    fn new() -> Self {
        let fixture = Self {
            home: tempfile::TempDir::new().unwrap(),
            local: kapsaro_test_support::fixture::setup_test_keystore_from_fixtures(
                crate::cli::common::ALICE_MEMBER_HANDLE,
            ),
        };
        fixture.command(&["init", "-g"]).assert().success();
        fixture
    }

    fn std_command(&self, args: &[&str]) -> std::process::Command {
        let mut command = crate::cli::common::kapsaro_std_cmd();
        command
            .args(args)
            .env("HOME", self.home.path())
            .env("KAPSARO_HOME", self.local.path())
            .env(
                "KAPSARO_SSH_IDENTITY",
                self.local.path().join(".ssh/test_ed25519"),
            );
        command
    }

    fn command(&self, args: &[&str]) -> assert_cmd::Command {
        assert_cmd::Command::from_std(self.std_command(args))
    }

    fn set(&self, name: &str, key: &str, value: &str) {
        let mut command = self.std_command(&["set", "--global", "-n", name, key, value]);
        crate::cli::common::assert_member_set_review_success(&mut command);
    }
}

#[cfg(unix)]
#[test]
fn test_global_init_reuses_members_without_local_identity_resolution() {
    let fixture = GlobalFixture::new();
    let unrelated = tempfile::TempDir::new().unwrap();
    fixture
        .command(&["init", "--global"])
        .arg("--home")
        .arg(unrelated.path().join("uncreated"))
        .env("KAPSARO_MEMBER_HANDLE", "invalid/handle")
        .assert()
        .success()
        .stderr(predicate::str::contains("Workspace already initialized"));
    assert_eq!(std::fs::read_dir(unrelated.path()).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn test_global_stores_run_and_import_use_selected_values_and_invocation_directory() {
    let fixture = GlobalFixture::new();
    let cwd = tempfile::TempDir::new().unwrap();
    fixture.set("default", "VALUE", "global-value");
    fixture.set("named", "VALUE", "named-value");
    fixture.set("named", "KAPSARO_EXPLICIT", "from-store");
    let regular = cwd.path().join("regular");
    fixture
        .command(&["init"])
        .arg("--workspace")
        .arg(&regular)
        .assert()
        .success();
    let mut regular_set = fixture.std_command(&["set", "-n", "named", "VALUE", "regular-value"]);
    regular_set.arg("--workspace").arg(&regular);
    crate::cli::common::assert_member_set_review_success(&mut regular_set);
    fixture
        .command(&["get", "-g", "VALUE"])
        .env("KAPSARO_WORKSPACE", cwd.path().join("missing"))
        .assert()
        .success()
        .stdout("global-value\n");
    fixture.command(&["run", "--global", "-n", "named", "--", "sh", "-c",
        "test \"$VALUE\" = named-value && test \"${KAPSARO_INHERITED-unset}\" = unset && test \"$KAPSARO_EXPLICIT\" = from-store && test . -ef \"$EXPECTED_CWD\" && exit 23"])
        .current_dir(cwd.path()).env("EXPECTED_CWD", cwd.path())
        .env("KAPSARO_WORKSPACE", &regular)
        .env("VALUE", "parent-value").env("KAPSARO_INHERITED", "parent-secret")
        .assert().code(23);
    std::fs::write(cwd.path().join("input.env"), "IMPORTED=relative-file\n").unwrap();
    fixture
        .command(&["import", "-g", "input.env"])
        .current_dir(cwd.path())
        .assert()
        .success();
    fixture
        .command(&["get", "--global", "IMPORTED"])
        .assert()
        .success()
        .stdout("relative-file\n");
    fixture
        .command(&["list", "-g"])
        .assert()
        .success()
        .stdout(predicate::str::contains("IMPORTED"));
    fixture
        .command(&["unset", "-g", "IMPORTED", "--force"])
        .assert()
        .success();
    fixture
        .command(&["get", "-g", "VALUE", "-n", "absent"])
        .assert()
        .failure();
}

#[cfg(unix)]
#[test]
fn test_global_store_is_shared_across_repositories_and_home() {
    let fixture = GlobalFixture::new();
    fixture.set("default", "VALUE", "shared-value");
    let first = tempfile::TempDir::new().unwrap();
    let second = tempfile::TempDir::new().unwrap();
    let outside = tempfile::TempDir::new().unwrap();
    for repository in [first.path(), second.path()] {
        assert!(std::process::Command::new("git")
            .args(["init", "--quiet"])
            .arg(repository)
            .status()
            .unwrap()
            .success());
    }
    for directory in [
        first.path(),
        second.path(),
        outside.path(),
        fixture.home.path(),
    ] {
        fixture
            .command(&["get", "--global", "VALUE"])
            .current_dir(directory)
            .assert()
            .success()
            .stdout("shared-value\n");
    }
}

#[cfg(unix)]
#[test]
fn test_global_run_rejects_invalid_artifact_before_starting_child() {
    let fixture = GlobalFixture::new();
    fixture.set("default", "VALUE", "global-value");
    let artifact = fixture.home.path().join(".kapsaro/secrets/default.kvenc");
    crate::cli::common::tamper_kv_signature(&artifact);
    let marker = fixture.home.path().join("child-started");
    fixture
        .command(&["run", "-g", "--", "sh", "-c", "touch \"$MARKER\""])
        .env("MARKER", &marker)
        .assert()
        .failure();
    assert!(!marker.exists());
}

#[cfg(unix)]
#[test]
#[serial_test::serial]
fn test_global_run_requires_recipient_approval_before_starting_child() {
    let fixture = crate::cli::common::setup_unapproved_kv_read_fixture();
    let home = tempfile::TempDir::new().unwrap();
    std::os::unix::fs::symlink(&fixture.workspace, home.path().join(".kapsaro")).unwrap();
    let marker = home.path().join("child-started");
    cmd()
        .args([
            "run",
            "--global",
            "--member-handle",
            crate::cli::common::ALICE_MEMBER_HANDLE,
            "--",
            "sh",
            "-c",
            "touch \"$MARKER\"",
        ])
        .env("HOME", home.path())
        .env("KAPSARO_HOME", fixture.home.path())
        .env("KAPSARO_SSH_IDENTITY", &fixture.ssh_identity)
        .env("KAPSARO_STRICT_KEY_CHECKING", "yes")
        .env("MARKER", &marker)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "Unknown recipient kid requires approval",
        ))
        .stdout(predicate::str::contains("must-not-print").not())
        .stderr(predicate::str::contains("must-not-print").not());
    assert!(!marker.exists());
    assert!(!fixture.trust_store_path.exists());
}

#[cfg(unix)]
#[test]
fn test_global_run_requires_active_membership_before_starting_child() {
    let fixture = GlobalFixture::new();
    fixture.set("default", "VALUE", "global-value");
    let active = fixture.home.path().join(".kapsaro/members/active");
    let member = active.join(format!("{}.json", crate::cli::common::ALICE_MEMBER_HANDLE));
    std::fs::remove_file(member).unwrap();
    let marker = fixture.home.path().join("child-started");
    fixture
        .command(&["run", "-g", "--", "sh", "-c", "touch \"$MARKER\""])
        .env("MARKER", &marker)
        .assert()
        .failure()
        .stdout(predicate::str::contains("global-value").not())
        .stderr(predicate::str::contains("global-value").not());
    assert!(!marker.exists());
}

#[cfg(unix)]
#[test]
fn test_global_init_rejects_invalid_existing_document_and_join_requires_workspace() {
    let home = tempfile::TempDir::new().unwrap();
    cmd()
        .args(["join", "-g"])
        .env("HOME", home.path())
        .assert()
        .failure();
    std::fs::create_dir_all(home.path().join(".kapsaro/members/active")).unwrap();
    let document = home.path().join(".kapsaro/members/active/invalid.json");
    std::fs::write(&document, "invalid public key").unwrap();
    cmd()
        .args(["init", "--global"])
        .env("HOME", home.path())
        .assert()
        .failure();
    assert_eq!(
        std::fs::read_to_string(document).unwrap(),
        "invalid public key"
    );
    assert!(!home.path().join(".kapsaro/secrets").exists());
}

#[test]
fn test_workspace_commands_advertise_global_selection() {
    for command in [
        "init", "join", "encrypt", "decrypt", "get", "set", "unset", "list", "import", "run",
        "rewrap",
    ] {
        cmd()
            .args([command, "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("-g, --global"));
    }
    for command in ["list", "add", "remove", "show", "verify"] {
        cmd()
            .args(["member", command, "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("-g, --global"));
    }
}

#[cfg(unix)]
#[test]
fn test_global_file_commands_resolve_relative_paths_from_invocation_directory() {
    let fixture = GlobalFixture::new();
    let cwd = tempfile::TempDir::new().unwrap();
    std::fs::write(cwd.path().join("input.txt"), b"relative payload").unwrap();
    let mut encrypt =
        fixture.std_command(&["encrypt", "-g", "input.txt", "--out", "encrypted.fileenc"]);
    encrypt.current_dir(cwd.path());
    crate::cli::common::assert_member_set_review_success(&mut encrypt);
    fixture
        .command(&[
            "decrypt",
            "--global",
            "encrypted.fileenc",
            "--out",
            "decrypted.txt",
        ])
        .current_dir(cwd.path())
        .assert()
        .success();
    assert_eq!(
        std::fs::read(cwd.path().join("decrypted.txt")).unwrap(),
        b"relative payload"
    );
}

#[test]
fn test_global_spellings_conflict_with_explicit_workspace() {
    let home = tempfile::TempDir::new().unwrap();
    for flag in ["--global", "-g"] {
        cmd()
            .args(["init", flag, "--workspace", "workspace"])
            .env("HOME", home.path())
            .assert()
            .code(2)
            .stderr(predicate::str::contains("cannot be used with"));
    }
}

#[test]
fn test_global_spellings_report_invalid_home() {
    for flag in ["--global", "-g"] {
        for value in [None, Some(""), Some("relative")] {
            let mut command = cmd();
            command.args(["list", flag]);
            match value {
                Some(value) => {
                    command.env("HOME", value);
                }
                None => {
                    command.env_remove("HOME");
                }
            }
            command.assert().failure().stderr(predicate::str::contains(
                "HOME must be set to a non-empty absolute path",
            ));
        }
    }
}
