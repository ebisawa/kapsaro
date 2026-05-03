// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Configuration types.
//!
//! Defines shared value types used while resolving secretenv configuration.

use serde::{Deserialize, Serialize};

/// Signing method configuration value
///
/// Represents the user's configured preference for SSH signing.
/// `Auto` selects ssh-agent if available, otherwise ssh-keygen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SshSigningMethodConfig {
    /// Automatically select based on ssh-agent availability
    #[default]
    Auto,
    /// Use ssh-agent protocol directly
    SshAgent,
    /// Use ssh-keygen -Y sign
    SshKeygen,
}

/// Signing method for SSH signature operations
///
/// This enum determines how SSH signatures are obtained for
/// LocalIdentityEncrypted operations (SA-SIG-KDF).
/// This is the resolved (concrete) method, not the user's configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshSigningMethod {
    /// Use ssh-agent protocol directly (method A)
    SshAgent,
    /// Use ssh-keygen -Y sign with SSHSIG parsing (method B)
    SshKeygen,
}

impl std::fmt::Display for SshSigningMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshSigningMethod::SshAgent => write!(f, "ssh-agent"),
            SshSigningMethod::SshKeygen => write!(f, "ssh-keygen"),
        }
    }
}

/// Strict key checking mode for read-path trust judgment.
///
/// Controls whether unknown kids require manual approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StrictKeyChecking {
    /// Require known_keys check (default)
    #[default]
    Yes,
    /// Skip known_keys check for read-path
    No,
}

/// Source of the resolved strict key checking mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StrictKeyCheckingSource {
    /// No explicit override was provided.
    #[default]
    Default,
    /// The mode came from an explicit environment variable.
    ExplicitEnv,
}

/// Strict key checking policy resolution with provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StrictKeyCheckingResolution {
    pub mode: StrictKeyChecking,
    pub source: StrictKeyCheckingSource,
}

impl StrictKeyCheckingResolution {
    pub const fn strict() -> Self {
        Self {
            mode: StrictKeyChecking::Yes,
            source: StrictKeyCheckingSource::Default,
        }
    }

    pub const fn explicit(mode: StrictKeyChecking) -> Self {
        Self {
            mode,
            source: StrictKeyCheckingSource::ExplicitEnv,
        }
    }

    pub const fn is_disabled(self) -> bool {
        matches!(self.mode, StrictKeyChecking::No)
    }
}
