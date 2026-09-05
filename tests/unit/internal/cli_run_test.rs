// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for CLI-owned child process execution.

use std::collections::BTreeMap;
use std::process::Command;

use kapsaro_core::api::secret::SecretString;

use crate::cli::run::{execute_child_command, set_child_environment};
use crate::test_utils::EnvGuard;

#[test]
fn test_set_child_environment_removes_parent_kapsaro_values_and_applies_secrets() {
    let _guard = EnvGuard::new(&["KAPSARO_PARENT_ONLY", "KAPSARO_FROM_ARTIFACT"]);
    std::env::set_var("KAPSARO_PARENT_ONLY", "parent-secret");
    std::env::set_var("KAPSARO_FROM_ARTIFACT", "parent-value");
    let secrets = BTreeMap::from([
        (
            "API_KEY".to_string(),
            SecretString::new("secret-value".to_string()),
        ),
        (
            "KAPSARO_FROM_ARTIFACT".to_string(),
            SecretString::new("artifact-value".to_string()),
        ),
    ]);
    let mut command = Command::new("unused");

    set_child_environment(&mut command, &secrets);

    let configured = command
        .get_envs()
        .map(|(key, value)| {
            (
                key.to_string_lossy().into_owned(),
                value.map(|value| value.to_string_lossy().into_owned()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(configured.get("KAPSARO_PARENT_ONLY"), Some(&None));
    assert_eq!(
        configured.get("KAPSARO_FROM_ARTIFACT"),
        Some(&Some("artifact-value".to_string()))
    );
    assert_eq!(
        configured.get("API_KEY"),
        Some(&Some("secret-value".to_string()))
    );
}

#[test]
fn test_execute_child_command_inherits_parent_env_and_applies_overrides() {
    let _guard = EnvGuard::new(&[
        "PATH",
        "HOME",
        "TERM",
        "KAPSARO_PRIVATE_KEY",
        "KAPSARO_HOME",
        "KAPSARO_EXPLICIT",
        "CUSTOM_PARENT_ENV",
    ]);
    std::env::set_var("PATH", "/usr/bin");
    std::env::set_var("HOME", "/tmp/test-home");
    std::env::set_var("TERM", "xterm-256color");
    std::env::set_var("KAPSARO_PRIVATE_KEY", "sensitive");
    std::env::set_var("KAPSARO_HOME", "/tmp/kapsaro-home");
    std::env::set_var("KAPSARO_EXPLICIT", "parent-value");
    std::env::set_var("CUSTOM_PARENT_ENV", "parent-value");

    let secrets = BTreeMap::from([
        (
            "PATH".to_string(),
            SecretString::new("/custom/bin".to_string()),
        ),
        (
            "KAPSARO_EXPLICIT".to_string(),
            SecretString::new("kv-value".to_string()),
        ),
    ]);
    let script = r#"test -z "$KAPSARO_PRIVATE_KEY" &&
        test -z "$KAPSARO_HOME" &&
        test "$PATH" = "/custom/bin" &&
        test "$HOME" = "/tmp/test-home" &&
        test "$TERM" = "xterm-256color" &&
        test "$CUSTOM_PARENT_ENV" = "parent-value" &&
        test "$KAPSARO_EXPLICIT" = "kv-value""#;
    let command = vec!["/bin/sh".to_string(), "-c".to_string(), script.to_string()];

    let code = execute_child_command(&command, &secrets).unwrap();

    assert_eq!(code, 0);
}

#[test]
fn test_execute_child_command_preserves_exit_code() {
    let command = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "exit 23".to_string(),
    ];

    let code = execute_child_command(&command, &BTreeMap::new()).unwrap();

    assert_eq!(code, 23);
}
