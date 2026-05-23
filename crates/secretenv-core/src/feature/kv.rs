// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV feature - get/set/unset/list operations.

pub mod builder;
pub mod decrypt;
pub(crate) mod document;
pub mod encrypt;
pub(crate) mod entry_codec;
pub(crate) mod error;
pub(crate) mod header;
pub mod mutate;
pub mod query;
pub(crate) mod rewrite_session;
pub(crate) mod sign;
pub mod types;
