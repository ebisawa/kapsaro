// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! CLI presentation API allow-list.
//! This module exposes formatting helpers used by the first-party CLI.

pub mod config {
    pub use crate::config::types::SshSigningMethod;
}

pub mod fs {
    pub use crate::support::fs::atomic::{save_bytes, save_text};
    pub use crate::support::fs::{load_bytes, load_text_with_limit};
}

pub mod kid {
    pub use crate::support::kid::{format_kid_display, format_kid_display_lossy};
}

pub mod limits {
    pub use crate::support::limits::{MAX_JSON_DOCUMENT_READ_SIZE, MAX_KV_ENC_FILE_SIZE};
}

pub mod path {
    pub use crate::support::path::format_path_relative_to_cwd;
}

pub mod ssh {
    pub use crate::model::ssh::SshDeterminismStatus;
}

pub mod tty {
    pub use crate::support::tty::is_interactive;
}

pub mod validation {
    pub use crate::support::validation::{validate_github_login, validate_member_handle};
}
