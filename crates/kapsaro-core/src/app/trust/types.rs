// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared types for trust-store mutations.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedKnownKey {
    pub member_handle: String,
    pub kid: String,
}
