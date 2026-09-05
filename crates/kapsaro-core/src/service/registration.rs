// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Member registration operations shared by API callers.

pub mod command;
pub mod key_plan;
pub mod types;
mod workspace;
pub use workspace::{
    ensure_init_workspace_structure, evaluate_init_workspace_status, InitWorkspaceState,
};

#[cfg(test)]
#[path = "../../tests/unit/internal/service_registration_test.rs"]
mod service_registration_test;
