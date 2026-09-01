// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public kv-enc artifact API.
//! Re-exports the stable service contract without implementation logic.

pub use crate::service::kv::{
    AuthorizedKvMutation, KvDisclosedEntry, KvEncArtifact, KvInputEntry, KvMutationOperation,
    KvReadOperation, TrustedKvEncArtifact, VerifiedKvEncArtifact,
};
