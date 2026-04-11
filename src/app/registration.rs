// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer member registration helpers for init/join flows.

pub(crate) mod command;
pub(crate) mod key_plan;
pub(crate) mod types;
mod workspace;

#[cfg(test)]
#[path = "../../tests/unit/app_registration_test.rs"]
mod tests;
