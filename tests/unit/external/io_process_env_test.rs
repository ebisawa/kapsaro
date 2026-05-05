// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use secretenv::io::process::execute_command_with_env;
use secretenv::support::secret::SecretString;
use std::collections::BTreeMap;

use crate::test_utils::EnvGuard;

#[test]
fn test_execute_command_with_env_inherits_parent_env_and_applies_overrides() {
    let _guard = EnvGuard::new(&[
        "PATH",
        "HOME",
        "TERM",
        "SECRETENV_PRIVATE_KEY",
        "SECRETENV_HOME",
        "SECRETENV_EXPLICIT",
        "CUSTOM_PARENT_ENV",
    ]);
    std::env::set_var("PATH", "/usr/bin");
    std::env::set_var("HOME", "/tmp/test-home");
    std::env::set_var("TERM", "xterm-256color");
    std::env::set_var("SECRETENV_PRIVATE_KEY", "sensitive");
    std::env::set_var("SECRETENV_HOME", "/tmp/secretenv-home");
    std::env::set_var("SECRETENV_EXPLICIT", "parent-value");
    std::env::set_var("CUSTOM_PARENT_ENV", "parent-value");

    let mut env_vars = BTreeMap::new();
    env_vars.insert(
        "PATH".to_string(),
        SecretString::new("/custom/bin".to_string()),
    );
    env_vars.insert(
        "SECRETENV_EXPLICIT".to_string(),
        SecretString::new("kv-value".to_string()),
    );

    let script = r#"test -z "$SECRETENV_PRIVATE_KEY" &&
        test -z "$SECRETENV_HOME" &&
        test "$PATH" = "/custom/bin" &&
        test "$HOME" = "/tmp/test-home" &&
        test "$TERM" = "xterm-256color" &&
        test "$CUSTOM_PARENT_ENV" = "parent-value" &&
        test "$SECRETENV_EXPLICIT" = "kv-value""#;
    let args = vec!["-c".to_string(), script.to_string()];

    let status = execute_command_with_env("/bin/sh", &args, &env_vars).unwrap();
    assert_eq!(status, 0);
}
