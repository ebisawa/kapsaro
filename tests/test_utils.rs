// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Test utilities for the CLI integration binary.
//! Re-exports the shared helpers so they live in exactly one place.

#[path = "test_utils/internal_cli.rs"]
#[allow(dead_code)]
pub mod internal_cli;

#[allow(unused_imports)]
pub use kapsaro_test_support::guards::{with_temp_cwd, EnvGuard, ENV_MUTEX};
#[allow(unused_imports)]
pub use kapsaro_test_support::workspace_state::{
    build_expiring_soon_timestamp, kid, member_handle, save_active_public_key_to_workspace,
    setup_trust_store_for_workspace, update_active_private_key_expires_at,
};
