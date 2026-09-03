// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Rewrap operations shared by API callers.

mod core;

pub use core::*;

mod plan;
pub(crate) mod promotion;
mod snapshot;
pub(crate) mod types;
