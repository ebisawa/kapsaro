// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared SSH-related model types.

/// Result of checking whether SSH signatures are deterministic enough for key protection.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SshDeterminismStatus {
    Verified,
    Skipped,
    Failed { message: String },
}
impl SshDeterminismStatus {
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified)
    }

    pub fn message(&self) -> Option<&str> {
        match self {
            Self::Verified | Self::Skipped => None,
            Self::Failed { message } => Some(message.as_str()),
        }
    }
}
