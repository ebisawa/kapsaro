// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! secretenv - Offline-first CLI for sharing encrypted .env files and other secrets through Git

pub mod cli;

#[cfg(test)]
extern crate self as secretenv;

#[cfg(test)]
#[allow(dead_code, unused_imports)]
#[path = "../tests/test_utils.rs"]
pub(crate) mod test_utils;

#[cfg(test)]
#[allow(dead_code, unused_imports)]
#[path = "../tests/test_utils/app_context.rs"]
pub(crate) mod app_test_utils;
