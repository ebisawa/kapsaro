// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Top-level CLI error presentation.

use secretenv_core::Error;

pub fn print_error(error: &Error) {
    eprintln!("Error: {}", error.format_user_message());
}
