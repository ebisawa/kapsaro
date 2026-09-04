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

pub(crate) use context_execution::{
    build_test_execution_context, build_test_member_approval_session,
    build_test_trust_command_session, build_test_trust_command_session_from_options,
    resolve_test_write_execution, resolve_test_write_session, TestWriteSession,
};
pub(crate) use context_options::{
    build_test_command_options, build_test_command_options_with,
    build_test_signing_command_options, TestCommandOptions,
};
pub(crate) use context_trust::load_test_trust_store;
// The trust store fixtures are shared with the root crate's CLI tests, so they
// live in kapsaro-test-support and reach service tests through this root.
pub(crate) use crate::test_utils::{
    build_known_key, build_recipient_set, save_trust_store_signed_by_active_key,
};
pub(crate) use keystore_documents::{
    build_test_private_key_document, build_test_public_key_document, OTHER_TEST_KEY_SIGNATURE,
    TEST_KEY_CREATED_AT, TEST_KEY_EXPIRES_AT, TEST_KEY_SIGNATURE,
};
pub(crate) use keystore_rotation::{add_generated_key, rotate_active_key};
