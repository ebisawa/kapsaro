// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Stable facade APIs for external applications.
//! Each module explicitly re-exports an allow-list from the internal service layer.

pub mod diagnostics;
pub mod file;
pub mod key;
pub mod kv;
pub mod online;
pub mod operation;
pub mod secret;
pub mod ssh;
pub mod trust;
