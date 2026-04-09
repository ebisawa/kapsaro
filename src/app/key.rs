// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer orchestration for key workflows.

pub(crate) mod export;
pub(crate) mod generate;
pub(crate) mod github;
pub(crate) mod manage;
pub(crate) mod timestamp;
pub(crate) mod types;

#[cfg(test)]
#[path = "../../tests/unit/app_key_github_test.rs"]
mod tests;
