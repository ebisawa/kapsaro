// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for `import` command

use crate::cli::common::{
    cmd, import_file_with_member_set_review, set_value_with_member_set_review, setup_workspace,
};
use predicates::prelude::*;
use std::fs;

#[test]
fn test_import_dotenv_file() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Create .env file
    let env_file = workspace_dir.path().join("test.env");
    fs::write(
        &env_file,
        "DB_URL=postgres://localhost\nAPI_KEY=secret123\nPORT=8080\n",
    )
    .unwrap();

    // Import
    let output = import_file_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        &env_file,
        false,
    );
    assert!(output.contains("Imported 3 entries"), "{output}");

    // Verify values can be retrieved
    for (key, expected_value) in &[
        ("DB_URL", "postgres://localhost"),
        ("API_KEY", "secret123"),
        ("PORT", "8080"),
    ] {
        cmd()
            .arg("get")
            .arg(key)
            .arg("--workspace")
            .arg(workspace_dir.path())
            .env("SECRETENV_HOME", home_dir.path())
            .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
            .assert()
            .success()
            .stdout(predicate::str::contains(*expected_value));
    }
}

#[test]
fn test_import_overwrites_existing_keys() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    // Set initial value
    set_value_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        "API_KEY",
        "old_value",
        None,
        None,
    );

    // Import file with same key
    let env_file = workspace_dir.path().join("test.env");
    fs::write(&env_file, "API_KEY=new_value\n").unwrap();

    cmd()
        .arg("import")
        .arg(env_file.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success();

    // Verify value was overwritten
    cmd()
        .arg("get")
        .arg("API_KEY")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("new_value"));
}

#[test]
fn test_import_invalid_dotenv_fails() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    let env_file = workspace_dir.path().join("bad.env");
    fs::write(&env_file, "VALID_KEY=value\nINVALID LINE WITHOUT EQUALS\n").unwrap();

    cmd()
        .arg("import")
        .arg(env_file.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains("missing '=' separator"));
}

#[test]
fn test_import_nonexistent_file_fails() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    cmd()
        .arg("import")
        .arg("/nonexistent/path/test.env")
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure();
}

#[test]
fn test_import_empty_file_fails() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    let env_file = workspace_dir.path().join("empty.env");
    fs::write(&env_file, "# only comments\n\n").unwrap();

    cmd()
        .arg("import")
        .arg(env_file.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains("No valid entries found"));
}

#[test]
fn test_import_with_json_output() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    let env_file = workspace_dir.path().join("test.env");
    fs::write(&env_file, "KEY1=value1\nKEY2=value2\n").unwrap();

    let output = import_file_with_member_set_review(
        workspace_dir.path(),
        home_dir.path(),
        &ssh_priv,
        &env_file,
        true,
    );
    assert!(output.contains("\"imported\""), "{output}");
    assert!(output.contains("\"file\""), "{output}");
}

#[test]
fn test_import_rejects_strict_key_checking_no() {
    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();

    let env_file = workspace_dir.path().join("strict.env");
    fs::write(&env_file, "KEY1=value1\n").unwrap();

    cmd()
        .arg("import")
        .arg(env_file.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .env("SECRETENV_STRICT_KEY_CHECKING", "no")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not allowed").and(predicate::str::contains("import")));
}

#[cfg(unix)]
#[test]
fn test_import_rejects_symlink_input_file() {
    use std::os::unix::fs::symlink;

    let (workspace_dir, home_dir, _ssh_temp, ssh_priv) = setup_workspace();
    let real_env = workspace_dir.path().join("real.env");
    let symlink_env = workspace_dir.path().join("symlink.env");
    fs::write(&real_env, "KEY1=value1\n").unwrap();
    symlink(&real_env, &symlink_env).unwrap();

    cmd()
        .arg("import")
        .arg(symlink_env.to_str().unwrap())
        .arg("--workspace")
        .arg(workspace_dir.path())
        .env("SECRETENV_HOME", home_dir.path())
        .env("SECRETENV_SSH_IDENTITY", ssh_priv.to_str().unwrap())
        .assert()
        .failure()
        .stderr(predicate::str::contains("symlink"));
}
