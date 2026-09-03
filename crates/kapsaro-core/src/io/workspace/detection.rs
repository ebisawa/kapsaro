// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Workspace detection logic.

mod resolution;
mod search;

pub use resolution::resolve_workspace;
pub(crate) use resolution::resolve_workspace_creation_path_from;
pub(crate) use search::detect_workspace_root;
pub use search::WorkspaceRoot;

#[cfg(test)]
#[path = "../../../tests/unit/internal/workspace_detection_internal_test.rs"]
mod internal_tests;

#[cfg(test)]
#[path = "../../../tests/unit/internal/workspace_detection_test.rs"]
mod workspace_detection_test;
