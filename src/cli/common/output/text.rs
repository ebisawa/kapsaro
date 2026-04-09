// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Text output helpers for CLI commands.

pub(crate) mod inspect;
pub(crate) mod key;
pub(crate) mod kv;
pub(crate) mod member;
pub(crate) mod registration;
pub(crate) mod rewrap;
pub(crate) mod trust;

pub(crate) fn print_optional_status(message: Option<&str>, quiet: bool) {
    if quiet {
        return;
    }
    if let Some(message) = message {
        eprintln!("{}", message);
    }
}

pub(crate) fn print_warnings(warnings: &[String]) {
    for warning in warnings {
        eprintln!("Warning: {}", warning);
    }
}
