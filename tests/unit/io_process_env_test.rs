// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use secretenv::io::process::execute_command_with_env;
use secretenv::support::secret::SecretString;
use std::collections::BTreeMap;

use crate::test_utils::EnvGuard;

#[test]
fn test_execute_command_with_env_filters_parent_env_and_applies_overrides() {
    let _guard = EnvGuard::new(&["PATH", "HOME", "TERM", "SECRETENV_PRIVATE_KEY"]);
    std::env::set_var("PATH", "/usr/bin");
    std::env::set_var("HOME", "/tmp/test-home");
    std::env::set_var("TERM", "xterm-256color");
    std::env::set_var("SECRETENV_PRIVATE_KEY", "sensitive");

    let mut env_vars = BTreeMap::new();
    env_vars.insert(
        "PATH".to_string(),
        SecretString::new("/custom/bin".to_string()),
    );

    let script = r#"test -z "$SECRETENV_PRIVATE_KEY" &&
        test "$PATH" = "/custom/bin" &&
        test "$HOME" = "/tmp/test-home" &&
        test "$TERM" = "xterm-256color""#;
    let args = vec!["-c".to_string(), script.to_string()];

    let status = execute_command_with_env("/bin/sh", &args, &env_vars).unwrap();
    assert_eq!(status, 0);
}
