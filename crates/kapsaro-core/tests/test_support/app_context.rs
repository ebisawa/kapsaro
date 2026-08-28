// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

#[path = "context_execution.rs"]
mod context_execution;
#[path = "../../../kapsaro-test-support/src/context_options.rs"]
mod context_options;
#[path = "context_paths.rs"]
mod context_paths;
#[path = "context_trust.rs"]
mod context_trust;
#[path = "keystore_documents.rs"]
mod keystore_documents;
#[path = "keystore_rotation.rs"]
mod keystore_rotation;

pub(crate) use context_execution::{build_test_execution_context, resolve_test_write_execution};
pub(crate) use context_options::{
    build_test_command_options, build_test_command_options_with, build_test_signing_command_options,
};
pub(crate) use context_trust::{
    load_test_trust_store, save_test_trust_store_signed_by_active_key,
    save_test_trust_store_with_recipient_sets,
};
pub(crate) use keystore_documents::{
    build_test_private_key_document, build_test_public_key_document, OTHER_TEST_KEY_SIGNATURE,
    TEST_KEY_CREATED_AT, TEST_KEY_EXPIRES_AT, TEST_KEY_SIGNATURE,
};
pub(crate) use keystore_rotation::{add_generated_key, rotate_active_key};
