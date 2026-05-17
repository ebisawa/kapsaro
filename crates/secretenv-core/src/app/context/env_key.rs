// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Env-key mode detection exposed to the CLI layer.

/// Returns true when env-var key mode is active (SECRETENV_PRIVATE_KEY set).
pub fn is_env_key_mode() -> bool {
    crate::feature::context::env_key::is_env_key_mode()
}
