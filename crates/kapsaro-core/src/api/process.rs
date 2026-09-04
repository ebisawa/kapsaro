// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public child-process environment isolation API.
//! Re-exports the stable service contract without implementation logic.

pub use crate::service::process::remove_parent_kapsaro_env_vars;
