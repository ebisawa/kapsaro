// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public workspace capability and path API.
//! Re-exports fixed write directories plus explicit validation and detection operations.

pub use crate::service::workspace::{
    detect_workspace_path, select_workspace_creation_path, validate_workspace_path,
    WorkspaceWriteDirectories,
};
