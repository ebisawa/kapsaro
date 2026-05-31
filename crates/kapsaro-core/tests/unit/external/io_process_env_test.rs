// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use kapsaro_core::cli_api::test_support::helpers::secret::SecretString;
use kapsaro_core::cli_api::test_support::storage::process::execute_command_with_env;
use std::collections::BTreeMap;

use crate::test_utils::EnvGuard;

#[test]
fn test_execute_command_with_env_inherits_parent_env_and_applies_overrides() {
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

    let mut env_vars = BTreeMap::new();
    env_vars.insert(
        "PATH".to_string(),
        SecretString::new("/custom/bin".to_string()),
    );
    env_vars.insert(
        "KAPSARO_EXPLICIT".to_string(),
        SecretString::new("kv-value".to_string()),
    );

    let script = r#"test -z "$KAPSARO_PRIVATE_KEY" &&
        test -z "$KAPSARO_HOME" &&
        test "$PATH" = "/custom/bin" &&
        test "$HOME" = "/tmp/test-home" &&
        test "$TERM" = "xterm-256color" &&
        test "$CUSTOM_PARENT_ENV" = "parent-value" &&
        test "$KAPSARO_EXPLICIT" = "kv-value""#;
    let args = vec!["-c".to_string(), script.to_string()];

    let status = execute_command_with_env("/bin/sh", &args, &env_vars).unwrap();
    assert_eq!(status, 0);
}
