// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Reusable standard operations shared by the public API and first-party app.
//! Accepts resolved inputs and capabilities without owning CLI orchestration.

pub(crate) mod artifact_text;
pub(crate) mod diagnostics;
pub(crate) mod file;
pub(crate) mod key;
pub(crate) mod kv;
pub(crate) mod online;
pub(crate) mod operation;
pub(crate) mod secret;
pub(crate) mod ssh;
pub(crate) mod trust;
