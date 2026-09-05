// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Child-process environment isolation offered as a standard operation.
//! Exposes the io-layer helper that strips inherited `KAPSARO_*` variables.

pub use crate::io::process::remove_parent_kapsaro_env_vars;
