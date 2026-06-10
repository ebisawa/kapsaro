// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Unit tests module
//!
//! This module contains external unit tests for core components organized as submodules.
//!
//! Each test file in crates/kapsaro-core/tests/unit/external/ must be explicitly declared below.
//! Tests under tests/unit/internal/ are registered from production modules with #[cfg(test)].
//! Modules are listed in alphabetical order for maintainability.

// Test utilities (must be declared before other modules to be available)
#[path = "test_support/mod.rs"]
pub mod test_utils;

// Key generation helpers (re-exported from test_utils to avoid duplicate module)
pub use test_utils::keygen_helpers;

#[path = "unit/external/api_artifact_load_policy_test.rs"]
pub mod api_artifact_load_policy_test;
#[path = "unit/external/app_key_manage_test.rs"]
pub mod app_key_manage_test;
#[path = "unit/external/format_token_encode_test.rs"]
pub mod format_token_encode_test;
#[path = "unit/external/model_identity_test.rs"]
pub mod model_identity_test;
#[path = "unit/external/model_ssh_test.rs"]
pub mod model_ssh_test;
#[path = "unit/external/ssh_protocol_key_descriptor_test.rs"]
pub mod ssh_protocol_key_descriptor_test;
#[path = "unit/external/ssh_test.rs"]
pub mod ssh_test;
