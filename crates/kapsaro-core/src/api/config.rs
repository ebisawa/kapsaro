// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public resolved configuration API.
//! Re-exports the stable service contract without implementation logic.

pub use crate::service::config::{
    list_config, resolve_config_value, set_config, unset_config, ConfigScope, ConfigSetResult,
    ConfigUnsetResult, LocalStateSession,
};
