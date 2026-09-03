// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV artifact operations shared by API callers.

mod core;

pub use core::{
    is_missing_key_error, load_import_text, resolve_kv_store_file_name, AuthorizedKvMutation,
    KvDisclosedEntry, KvEncArtifact, KvGetResult, KvInputEntry, KvMutationOperation,
    KvReadOperation, TrustedKvEncArtifact, VerifiedKvEncArtifact,
};

pub mod mutation;
pub mod session;
pub mod types;
