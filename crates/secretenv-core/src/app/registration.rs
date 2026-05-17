// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer member registration helpers for init/join commands.

pub mod command;
pub mod key_plan;
pub mod types;
mod workspace;
pub use workspace::{
    ensure_init_workspace_structure, evaluate_init_workspace_status, InitWorkspaceState,
};

#[cfg(test)]
#[path = "../../tests/unit/internal/app_registration_test.rs"]
mod tests;
