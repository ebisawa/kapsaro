// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Result types the KV use cases hand back to callers.
//! Carries mutation outcomes without presentation-specific conversion types.

#[derive(Debug)]
pub struct KvWriteOutcome {
    pub message: Option<String>,
}

#[derive(Debug)]
pub struct KvImportResult {
    pub write_outcome: KvWriteOutcome,
    pub entry_count: usize,
}
