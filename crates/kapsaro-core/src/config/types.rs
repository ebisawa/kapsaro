// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Configuration types.
//!
//! Defines shared value types used while resolving kapsaro configuration.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};

const GITHUB_USER_TYPO_ALIAS: &str = "gihub_user";

/// Supported flat global config key.
///
/// Centralizes canonical names and accepted aliases for config.toml keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigKey {
    MemberHandle,
    Workspace,
    SshIdentity,
    SshKeygenCommand,
    SshAddCommand,
    SshSigningMethod,
    GithubUser,
    AllowExpiredKey,
    AllowNonMember,
}

impl ConfigKey {
    const ALL: [Self; 9] = [
        Self::MemberHandle,
        Self::Workspace,
        Self::SshIdentity,
        Self::SshKeygenCommand,
        Self::SshAddCommand,
        Self::SshSigningMethod,
        Self::GithubUser,
        Self::AllowExpiredKey,
        Self::AllowNonMember,
    ];

    /// Return the canonical global config.toml key names.
    pub fn canonical_names() -> &'static [&'static str] {
        &[
            "member_handle",
            "workspace",
            "ssh_identity",
            "ssh_keygen_command",
            "ssh_add_command",
            "ssh_signing_method",
            "github_user",
            "allow_expired_key",
            "allow_non_member",
        ]
    }

    /// Parse a user-provided config key and normalize accepted aliases.
    pub fn parse(key: &str) -> Result<Self> {
        if key == GITHUB_USER_TYPO_ALIAS {
            return Ok(Self::GithubUser);
        }
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.canonical_name() == key)
            .ok_or_else(|| build_invalid_config_key_error(key))
    }

    /// Return the canonical config.toml key name.
    pub const fn canonical_name(self) -> &'static str {
        match self {
            Self::MemberHandle => "member_handle",
            Self::Workspace => "workspace",
            Self::SshIdentity => "ssh_identity",
            Self::SshKeygenCommand => "ssh_keygen_command",
            Self::SshAddCommand => "ssh_add_command",
            Self::SshSigningMethod => "ssh_signing_method",
            Self::GithubUser => "github_user",
            Self::AllowExpiredKey => "allow_expired_key",
            Self::AllowNonMember => "allow_non_member",
        }
    }
}

fn build_invalid_config_key_error(key: &str) -> Error {
    Error::build_invalid_argument_error(format!(
        "invalid key '{}'. Valid keys: {}",
        key,
        ConfigKey::canonical_names().join(", ")
    ))
}

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

#[cfg(test)]
#[path = "../../tests/unit/internal/config_types_test.rs"]
mod config_types_test;
