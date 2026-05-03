// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared types for trust-store mutations.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedKnownKey {
    pub member_handle: String,
    pub kid: String,
}

#[derive(Debug)]
pub struct TrustMutationResult<T> {
    pub value: T,
    pub warnings: Vec<String>,
}

impl<T> TrustMutationResult<T> {
    pub fn new(value: T, warnings: Vec<String>) -> Self {
        Self { value, warnings }
    }
}
