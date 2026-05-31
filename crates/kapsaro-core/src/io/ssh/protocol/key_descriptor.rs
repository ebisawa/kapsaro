// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SSH key descriptor types
//!
//! This module provides type-safe wrappers for SSH key paths, distinguishing
//! between private keys and public keys at the type level.

use crate::support::path::format_path_relative_to_cwd;
use crate::{Error, Result};
use std::path::{Path, PathBuf};

impl From<PathBuf> for SshKeyDescriptor {
    fn from(path: PathBuf) -> Self {
        Self::from_path(path)
    }
}

/// Describes an SSH key with type-level guarantees
///
/// This enum distinguishes between private key files and public key files,
/// enabling compile-time and runtime checks to prevent misuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshKeyDescriptor {
    /// Private key file (can derive public key, can sign)
    PrivateKey(SshPrivateKeyPath),
    /// Public key file (read-only, encryption/verification only)
    PublicKey(SshPublicKeyPath),
}

/// Type-safe wrapper for private key paths
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshPrivateKeyPath {
    path: PathBuf,
}

/// Type-safe wrapper for public key paths
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshPublicKeyPath {
    path: PathBuf,
}

impl SshKeyDescriptor {
    /// Create a descriptor from a path, auto-detecting the key type
    ///
    /// Files ending in .pub are treated as public keys, others as private keys.
    ///
    /// # Edge Cases
    ///
    /// - Files with non-UTF-8 extensions are treated as private keys
    /// - File named exactly `.pub` is treated as a public key (edge case)
    /// - Files like `key.pub.backup` are treated as private keys (extension is "backup", not "pub")
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use std::path::PathBuf;
    /// use kapsaro_core::io::ssh::protocol::key_descriptor::SshKeyDescriptor;
    ///
    /// let private_key = SshKeyDescriptor::from_path(PathBuf::from("~/.ssh/id_ed25519"));
    /// assert!(private_key.is_private_key_file());
    ///
    /// let public_key = SshKeyDescriptor::from_path(PathBuf::from("~/.ssh/id_ed25519.pub"));
    /// assert!(public_key.is_public_key_file());
    /// ```
    pub fn from_path(path: PathBuf) -> Self {
        if path.extension().and_then(|s| s.to_str()) == Some("pub") {
            Self::PublicKey(SshPublicKeyPath::new(path))
        } else {
            Self::PrivateKey(SshPrivateKeyPath::new(path))
        }
    }

    /// For signing operations - extracts private key or errors
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidOperation` if this descriptor represents a public key.
    pub fn require_private_key(&self) -> Result<&SshPrivateKeyPath> {
        match self {
            Self::PrivateKey(pk) => Ok(pk),
            Self::PublicKey(pubk) => Err(Error::build_invalid_operation_error(format!(
                "Signing requires a private key.\n\
                 Reason: public key was provided.\n\
                 Provided public key: {}\n\
                 Action: Use the key file without the .pub extension.",
                format_path_relative_to_cwd(&pubk.path)
            ))),
        }
    }

    /// Get the key file path
    ///
    /// Returns the path regardless of whether this is a private or public key.
    /// - For private keys: returns the private key path
    /// - For public keys: returns the public key path
    ///
    /// Use this when the operation can work with either key type (e.g., ssh-keygen -Y sign
    /// accepts both private keys and public keys, using ssh-agent for the latter).
    pub fn as_path(&self) -> &Path {
        match self {
            Self::PrivateKey(pk) => pk.as_path(),
            Self::PublicKey(pk) => pk.as_path(),
        }
    }

    /// Convert to PathBuf
    ///
    /// Returns the path as PathBuf regardless of whether this is a private or public key.
    pub fn to_path_buf(&self) -> PathBuf {
        self.as_path().to_path_buf()
    }

    /// For operations requiring a public key - extracts public key or errors
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidOperation` if this descriptor represents a private key.
    pub fn require_public_key(&self) -> Result<&SshPublicKeyPath> {
        match self {
            Self::PublicKey(pk) => Ok(pk),
            Self::PrivateKey(privk) => Err(Error::build_invalid_operation_error(format!(
                "Operation requires a public key, but a private key was provided: {}\n\
                    Hint: Use the public key file (with .pub extension) for this operation.",
                format_path_relative_to_cwd(&privk.path)
            ))),
        }
    }

    /// Check if this descriptor represents a public key file
    pub fn is_public_key_file(&self) -> bool {
        matches!(self, Self::PublicKey(_))
    }

    /// Check if this descriptor represents a private key file
    pub fn is_private_key_file(&self) -> bool {
        matches!(self, Self::PrivateKey(_))
    }
}

impl SshPrivateKeyPath {
    /// Create a new private key path
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Get the path as a reference
    pub fn as_path(&self) -> &Path {
        self.path.as_path()
    }

    /// Convert to PathBuf
    pub fn into_path_buf(self) -> PathBuf {
        self.path
    }
}

impl SshPublicKeyPath {
    /// Create a new public key path
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Get the path as a reference
    pub fn as_path(&self) -> &Path {
        self.path.as_path()
    }

    /// Convert to PathBuf
    pub fn into_path_buf(self) -> PathBuf {
        self.path
    }
}
