// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KV v9 models.

pub mod document;
pub mod entry;
pub mod header;
pub mod line;
pub mod verified;

#[cfg(test)]
#[path = "../../tests/unit/internal/model_kv_enc_internal_test.rs"]
mod internal_tests;
