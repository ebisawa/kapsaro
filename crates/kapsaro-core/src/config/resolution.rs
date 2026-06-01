// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Configuration resolution.
//!
//! Provides resolution functions for various configuration values based on priority order:
//! 1. CLI arguments/options
//! 2. Environment variables
//! 3. Global config (KAPSARO_HOME/config.toml)
//! 4. Default values

pub(crate) mod allow_expired_key;
pub(crate) mod allow_non_member;
pub(crate) mod common;
pub(crate) mod github_user;
pub(crate) mod global;
pub(crate) mod member_handle;
pub(crate) mod ssh_key;
pub(crate) mod ssh_signing_method;
pub(crate) mod strict_key_checking;
pub(crate) mod workspace;
