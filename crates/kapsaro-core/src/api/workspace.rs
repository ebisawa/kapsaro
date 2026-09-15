// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public workspace capability and path API.
//! Re-exports fixed write directories plus explicit validation and detection operations.

pub use crate::service::workspace::{
    detect_workspace_candidate_path, detect_workspace_path, detect_workspace_path_excluding,
    resolve_workspace_path, select_workspace_creation_path, WorkspaceAccess,
    WorkspaceCreationTarget, WorkspaceKind, WorkspaceWriteDirectories, SECRETS_DIR_NAME,
};
