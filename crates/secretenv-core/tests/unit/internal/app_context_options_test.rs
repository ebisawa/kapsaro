// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use super::CommonCommandOptions;

#[test]
fn test_operation_options_copies_non_secret_operation_controls() {
    let options = CommonCommandOptions {
        home: Some(PathBuf::from("/tmp/secretenv-home")),
        identity: None,
        debug: true,
        verbose: false,
        workspace: None,
        ssh_signing_method: None,
        allow_expired_key: true,
        allow_non_member: false,
    };

    let operation_options = options.operation_options();

    assert!(operation_options.debug());
    assert!(operation_options.allow_expired_key());
}
