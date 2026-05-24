// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV feature - encryption, mutation, rewrap, and query operations.

pub mod decrypt;
pub mod encrypt;
pub(crate) mod entry_codec;
pub(crate) mod error;
pub(crate) mod header;
pub mod mutate;
pub mod query;
pub(crate) mod rewrite_session;
pub(crate) mod sign;
pub mod types;
