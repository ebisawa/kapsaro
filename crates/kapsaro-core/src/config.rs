// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Configuration model and resolution logic.
//!
//! Defines the configuration key vocabulary and loads configured values from a
//! local state root the caller has already chosen. Callers normalize the key
//! spelling here rather than at each entry point that reads a value.

pub(crate) mod resolution;
pub(crate) mod types;
