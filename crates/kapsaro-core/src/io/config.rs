// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Configuration module.
//!
//! Provides configuration loading and management for kapsaro.
//! Config file location: `$KAPSARO_HOME/config.toml` or `~/.config/kapsaro/config.toml`
//!
//! Global config helpers for the flat key-value TOML format.

pub mod paths;
pub mod store;
