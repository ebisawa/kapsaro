// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Workspace detection logic.

mod resolution;
mod search;

pub use resolution::{
    resolve_optional_workspace, resolve_optional_workspace_with_base, resolve_workspace,
    resolve_workspace_creation_path, resolve_workspace_with_base,
};
pub use search::{detect_workspace_root, WorkspaceRoot};

#[cfg(test)]
#[path = "../../../tests/unit/internal/workspace_detection_internal_test.rs"]
mod internal_tests;
