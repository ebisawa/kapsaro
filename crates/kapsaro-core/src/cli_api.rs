// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! First-party CLI API boundary.
//!
//! This module is available only with the `cli-internal` feature. It is not part
//! of the external embedding API.

pub mod app;
pub mod presentation;

#[cfg(any(feature = "cli-test-support", test))]
#[doc(hidden)]
pub mod test_support;
