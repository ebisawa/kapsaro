// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared operation options for facade APIs.

/// Non-secret operation controls shared by facade methods.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OperationOptions {
    allow_expired_key: bool,
}

impl OperationOptions {
    /// Build default operation options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Explicitly allow expired keys on operational read/verification paths.
    pub fn with_allow_expired_key(mut self, allow_expired_key: bool) -> Self {
        self.allow_expired_key = allow_expired_key;
        self
    }

    /// Return whether expired keys are explicitly allowed.
    pub fn allow_expired_key(&self) -> bool {
        self.allow_expired_key
    }
}
