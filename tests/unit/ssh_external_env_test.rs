// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use secretenv::io::ssh::external::add::DefaultSshAdd;
use secretenv::io::ssh::external::keygen::DefaultSshKeygen;
use secretenv::io::ssh::external::traits::SshAdd;
use secretenv::io::ssh::external::traits::SshKeygen;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

use crate::test_utils::EnvGuard;

fn make_env_dump_script() -> (TempDir, String) {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("dump-env.sh");
    fs::write(&script_path, "#!/bin/sh\nenv\n").unwrap();
    let mut perms = fs::metadata(&script_path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script_path, perms).unwrap();
    (temp_dir, script_path.to_string_lossy().into_owned())
}

#[test]
fn test_load_ssh_public_key_from_keygen_uses_sanitized_env_with_optional_socket() {
    let _guard = EnvGuard::new(&["HOME", "PATH", "SSH_AUTH_SOCK", "SECRETENV_PRIVATE_KEY"]);
    let fake_home = TempDir::new().unwrap();
    std::env::set_var("HOME", fake_home.path());
    std::env::set_var("PATH", "/usr/bin");
    std::env::set_var("SSH_AUTH_SOCK", "/tmp/agent.sock");
    std::env::set_var("SECRETENV_PRIVATE_KEY", "sensitive");

    let (_script_dir, script_path) = make_env_dump_script();
    let output = DefaultSshKeygen::new(&script_path)
        .derive_public_key(std::path::Path::new("/tmp/test-key"))
        .unwrap();

    assert!(output.contains("PATH=/usr/bin"));
    assert!(output.contains("SSH_AUTH_SOCK=/tmp/agent.sock"));
    assert!(!output.contains("SECRETENV_PRIVATE_KEY=sensitive"));
}

#[test]
fn test_default_ssh_add_sets_resolved_socket_without_inheriting_secret_env() {
    let _guard = EnvGuard::new(&["HOME", "PATH", "SSH_AUTH_SOCK", "SECRETENV_PRIVATE_KEY"]);
    let fake_home = TempDir::new().unwrap();
    std::env::set_var("HOME", fake_home.path());
    std::env::set_var("PATH", "/usr/bin");
    std::env::set_var("SSH_AUTH_SOCK", "/tmp/agent.sock");
    std::env::set_var("SECRETENV_PRIVATE_KEY", "sensitive");

    let (_script_dir, script_path) = make_env_dump_script();
    let ssh_add = DefaultSshAdd::new(script_path);
    let output = ssh_add.list_keys().unwrap();

    assert!(output.contains("PATH=/usr/bin"));
    assert!(output.contains("SSH_AUTH_SOCK=/tmp/agent.sock"));
    assert!(!output.contains("SECRETENV_PRIVATE_KEY=sensitive"));
}
