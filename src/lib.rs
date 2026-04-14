// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! secretenv - Offline-first CLI for sharing encrypted .env files and other secrets through Git

pub(crate) mod app;
pub mod cli;
pub mod config;
pub mod crypto;
pub mod error;
pub mod feature;
pub mod format;
pub mod io;
pub mod model;
pub mod support;

pub use error::{Error, Result};

#[cfg(test)]
extern crate self as secretenv;

#[cfg(test)]
#[path = "../tests/test_utils.rs"]
pub(crate) mod test_utils;

#[cfg(test)]
#[path = "../tests/test_utils/app_context.rs"]
pub(crate) mod app_test_utils;
