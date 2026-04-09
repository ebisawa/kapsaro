// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared helpers for verified KV rewrites and re-signing.

mod encrypt;
mod history;
mod session;
mod unsigned;

pub(crate) use encrypt::encrypt_kv_map_with_key_context;
pub(crate) use session::{KvRecipientRewriteRequest, VerifiedKvRewriteSession};
