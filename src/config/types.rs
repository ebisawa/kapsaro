// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Configuration types (Phase 10 - TDD Refactor phase)
//!
//! Defines the data structures for secretenv configuration.

use serde::{Deserialize, Serialize};

/// Default ssh-add command path
const DEFAULT_SSH_ADD_PATH: &str = "ssh-add";

/// Default ssh-keygen command path
const DEFAULT_SSH_KEYGEN_PATH: &str = "ssh-keygen";

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

/// SSH-related configuration
///
/// Controls how secretenv interacts with SSH tooling for signature operations.
/// All fields have sensible defaults and can be omitted in TOML.
///
/// # Default Values
///
/// - `ssh_add_path`: `"ssh-add"`
/// - `ssh_keygen_path`: `"ssh-keygen"`
/// - `ssh_signing_method`: `SshSigningMethodConfig::Auto`
///
/// # TOML Example
///
/// ```toml
/// [ssh]
/// ssh_add_path = "/usr/local/bin/ssh-add"
/// ssh_keygen_path = "/usr/local/bin/ssh-keygen"
/// ssh_signing_method = "auto"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfig {
    /// Path to ssh-add command
    ///
    /// Used for listing loaded SSH keys (`ssh-add -L`).
    /// Default: `"ssh-add"`
    #[serde(default = "default_ssh_add_path")]
    pub ssh_add_path: String,

    /// Path to ssh-keygen command
    ///
    /// Used for `ssh-keygen -Y sign` operations when `ssh_signing_method` is `SshKeygen`.
    /// Default: `"ssh-keygen"`
    #[serde(default = "default_ssh_keygen_path")]
    pub ssh_keygen_path: String,

    /// Signing method to use
    ///
    /// Determines how SSH signatures are obtained for LocalIdentityEncrypted.
    /// Default: `SshSigningMethodConfig::Auto`
    #[serde(default, rename = "ssh_signing_method")]
    pub signing_method: SshSigningMethodConfig,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            ssh_add_path: DEFAULT_SSH_ADD_PATH.to_string(),
            ssh_keygen_path: DEFAULT_SSH_KEYGEN_PATH.to_string(),
            signing_method: SshSigningMethodConfig::default(),
        }
    }
}

fn default_ssh_add_path() -> String {
    DEFAULT_SSH_ADD_PATH.to_string()
}

fn default_ssh_keygen_path() -> String {
    DEFAULT_SSH_KEYGEN_PATH.to_string()
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

/// Top-level configuration document
///
/// Root structure for `~/.config/secretenv/config.toml`.
///
/// # Format
///
/// Must include `format = "secretenv/config@1"` for version validation.
/// `member_handle` is required.
/// The `ssh` section is optional and uses defaults if omitted.
///
/// # TOML Example
///
/// ```toml
/// format = "secretenv/config@1"
/// member_handle = "alice@example.com"
///
/// [ssh]
/// ssh_signing_method = "auto"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigDocument {
    /// Format version (must be "secretenv/config@1")
    ///
    /// Used for forward compatibility. Loading will fail if format is unsupported.
    pub format: String,

    /// Member handle
    ///
    /// User-facing selector used across SecretEnv workspaces.
    pub member_handle: String,

    /// SSH configuration
    ///
    /// Controls SSH signing behavior. Defaults to `SshConfig::default()` if omitted.
    #[serde(default)]
    pub ssh: SshConfig,
}
