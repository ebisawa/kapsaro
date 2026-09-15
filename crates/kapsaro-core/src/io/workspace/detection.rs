// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Workspace detection logic.

mod resolution;
mod search;

pub use resolution::resolve_workspace;
pub(crate) use resolution::resolve_workspace_creation_path_from;
pub(crate) use search::detect_workspace_candidate_root_filtered;
pub(crate) use search::detect_workspace_root;
pub(crate) use search::detect_workspace_root_filtered;
pub use search::WorkspaceRoot;

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_workspace_detection_internal_test.rs"]
mod io_workspace_detection_internal_test;

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_workspace_detection_test.rs"]
mod io_workspace_detection_test;
