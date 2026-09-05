// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

// Module root for CLI integration test helpers.
// Re-exports all public symbols from the responsibility-focused submodules.

pub mod artifact;
pub mod execution;
pub mod review;
pub mod workspace;

/// Storage timestamp every CLI trust store fixture is written with.
///
/// A fixed value keeps the stored document byte-identical across runs, so a
/// test that compares two saves sees only the fields it changed.
pub const TRUST_STORE_STORED_AT: &str = "2026-03-29T12:34:56Z";

pub use artifact::{assert_stderr_order, tamper_kv_signature};
#[cfg(unix)]
pub use artifact::{setup_unapproved_file_read_fixture, setup_unapproved_kv_read_fixture};
pub use execution::cmd;
#[cfg(unix)]
pub use execution::{
    kapsaro_bin, kapsaro_std_cmd, run_command_with_optional_prompt_pty, run_command_with_pty,
    run_command_with_pty_script, run_command_with_pty_script_at_prompt,
};
pub use kapsaro_test_support::constants::{
    ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE, CAROL_MEMBER_HANDLE, TEST_MEMBER_HANDLE,
};
pub use kapsaro_test_support::trust_store_state::save_trust_store_signed_by_active_key;
#[cfg(unix)]
pub use review::{
    assert_member_set_review_success, encrypt_file_with_member_set_review,
    encrypt_stdin_with_member_set_review, import_file_with_member_set_review,
    set_stdin_with_member_set_review, set_value_with_member_set_review,
};
#[cfg(unix)]
pub use workspace::{append_common_command_args, setup_workspace_with_kv_entries};
pub use workspace::{
    copy_dir_all, default_common_options, generate_temp_ssh_keypair, set_ssh_key_from_temp_dir,
    setup_secret_home, setup_workspace, CommonOptions,
};
