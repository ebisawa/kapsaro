// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(feature = "cli-internal"), allow(dead_code, unused_imports))]

//! Core library APIs for SecretEnv encrypted artifacts and local state.

pub mod api;
pub mod error;
pub mod prelude;

#[cfg(any(feature = "cli-internal", test))]
#[doc(hidden)]
pub mod cli_api;

#[allow(dead_code, unused_imports)]
mod app;
#[allow(dead_code, unused_imports)]
pub(crate) mod config;
#[allow(dead_code, unused_imports)]
pub(crate) mod crypto;
#[allow(dead_code, unused_imports)]
pub(crate) mod feature;
#[allow(dead_code, unused_imports)]
pub(crate) mod format;
#[allow(dead_code, unused_imports)]
pub(crate) mod io;
#[allow(dead_code, unused_imports)]
pub(crate) mod model;
#[allow(dead_code, unused_imports)]
pub(crate) mod support;

pub use error::{Error, ErrorKind, Result};

#[cfg(test)]
extern crate self as secretenv;

#[cfg(test)]
extern crate self as secretenv_core;

#[cfg(test)]
#[allow(dead_code, unused_imports)]
#[path = "../tests/test_support/mod.rs"]
pub(crate) mod test_utils;

#[cfg(test)]
#[allow(dead_code, unused_imports)]
#[path = "../tests/test_support/app_context.rs"]
pub(crate) mod app_test_utils;
