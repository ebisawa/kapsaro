// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::rewrap::RewrapBatchCommandInput;
use crate::app_test_utils::{build_test_signing_command_options, resolve_test_write_execution};
use crate::test_utils::{setup_test_workspace, EnvGuard};

const ALICE_MEMBER_HANDLE: &str = "alice@example.com";

fn strict_key_checking_guard() -> EnvGuard {
    let guard = EnvGuard::new(&["SECRETENV_STRICT_KEY_CHECKING"]);
    std::env::remove_var("SECRETENV_STRICT_KEY_CHECKING");
    guard
}

#[test]
fn test_build_rewrap_batch_request_preserves_command_flags() {
    let _guard = strict_key_checking_guard();
    let (temp_dir, workspace_dir) = setup_test_workspace(&[ALICE_MEMBER_HANDLE]);
    let options = build_test_signing_command_options(temp_dir.path(), &workspace_dir);
    let execution = resolve_test_write_execution(&options, ALICE_MEMBER_HANDLE);
    let input = RewrapBatchCommandInput {
        options: options.clone(),
        execution,
        rotate_key: true,
        clear_disclosure_history: true,
        explicit_targets: Vec::new(),
    };

    let request = super::build_rewrap_batch_request(&input);

    assert_eq!(request.options.home, options.home);
    assert!(request.rotate_key);
    assert!(request.clear_disclosure_history);
    assert!(request.accepted_promotions.is_empty());
}
