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
#[path = "unit/external/api_trust_store_mutation_test.rs"]
pub mod api_trust_store_mutation_test;
#[path = "unit/external/app_key_manage_test.rs"]
pub mod app_key_manage_test;
#[path = "unit/external/crypto_kdf_test.rs"]
pub mod crypto_kdf_test;
#[path = "unit/external/crypto_sign_ed25519_test.rs"]
pub mod crypto_sign_ed25519_test;
#[path = "unit/external/crypto_test.rs"]
pub mod crypto_test;
#[path = "unit/external/crypto_types_test.rs"]
pub mod crypto_types_test;
#[path = "unit/external/crypto_xchacha20_poly1305_test.rs"]
pub mod crypto_xchacha20_poly1305_test;
#[path = "unit/external/error_display_test.rs"]
pub mod error_display_test;
#[path = "unit/external/error_test.rs"]
pub mod error_test;
#[path = "unit/external/format_token_encode_test.rs"]
pub mod format_token_encode_test;
#[path = "unit/external/model_identity_test.rs"]
pub mod model_identity_test;
#[path = "unit/external/model_ssh_test.rs"]
pub mod model_ssh_test;
#[path = "unit/external/ssh_agent_socket_test.rs"]
pub mod ssh_agent_socket_test;
#[path = "unit/external/ssh_agent_validation_test.rs"]
pub mod ssh_agent_validation_test;
#[path = "unit/external/ssh_external_env_test.rs"]
pub mod ssh_external_env_test;
#[path = "unit/external/ssh_external_pubkey_test.rs"]
pub mod ssh_external_pubkey_test;
#[path = "unit/external/ssh_openssh_config_integration_test.rs"]
pub mod ssh_openssh_config_integration_test;
#[path = "unit/external/ssh_openssh_config_test.rs"]
pub mod ssh_openssh_config_test;
#[path = "unit/external/ssh_parse_test.rs"]
pub mod ssh_parse_test;
#[path = "unit/external/ssh_protection_test.rs"]
pub mod ssh_protection_test;
#[path = "unit/external/ssh_protocol_key_descriptor_test.rs"]
pub mod ssh_protocol_key_descriptor_test;
#[path = "unit/external/ssh_protocol_types_test.rs"]
pub mod ssh_protocol_types_test;
#[path = "unit/external/ssh_test.rs"]
pub mod ssh_test;
#[path = "unit/external/ssh_verify_test.rs"]
pub mod ssh_verify_test;
#[path = "unit/external/support_codec_base64_test.rs"]
pub mod support_codec_base64_test;
#[path = "unit/external/support_display_sanitize_test.rs"]
pub mod support_display_sanitize_test;
#[path = "unit/external/support_fs_atomic_error_test.rs"]
pub mod support_fs_atomic_error_test;
#[path = "unit/external/support_fs_atomic_test.rs"]
pub mod support_fs_atomic_test;
#[path = "unit/external/support_fs_lock_error_test.rs"]
pub mod support_fs_lock_error_test;
#[path = "unit/external/support_fs_lock_test.rs"]
pub mod support_fs_lock_test;
#[path = "unit/external/support_fs_test.rs"]
pub mod support_fs_test;
#[path = "unit/external/support_kid_test.rs"]
pub mod support_kid_test;
#[path = "unit/external/support_secret_test.rs"]
pub mod support_secret_test;
#[path = "unit/external/support_time_test.rs"]
pub mod support_time_test;
#[path = "unit/external/support_validation_test.rs"]
pub mod support_validation_test;
#[path = "unit/external/test_utils_ed25519_backend_test.rs"]
pub mod test_utils_ed25519_backend_test;
#[cfg(feature = "online")]
#[path = "unit/external/verify_github_test.rs"]
pub mod verify_github_test;
