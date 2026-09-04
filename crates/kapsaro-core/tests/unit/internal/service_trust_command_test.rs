// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for the fixed-capability trust command session.
//! Verifies that owner and local-state identities cannot be mixed.

use super::TrustCommandSession;
use crate::service::config::LocalStateSession;
use crate::service::key::KeyContext;
use crate::test_utils::{
    member_handle, setup_member_key_context, setup_test_keystore_from_fixtures,
};
use std::sync::Arc;

const ALICE: &str = "alice@example.com";
const BOB: &str = "bob@example.com";

#[test]
fn test_trust_command_session_rejects_another_owner() {
    let home = setup_test_keystore_from_fixtures(ALICE);
    let key_ctx = KeyContext::from_inner(setup_member_key_context(&home, ALICE, None));

    let local_state = LocalStateSession::open(home.path().to_path_buf()).unwrap();
    let error = TrustCommandSession::open(&local_state, member_handle(BOB), key_ctx)
        .err()
        .expect("another owner must be rejected");

    assert_eq!(error.kind(), crate::ErrorKind::InvalidArgument);
}

#[test]
fn test_trust_command_session_rejects_another_local_state_home() {
    let key_home = setup_test_keystore_from_fixtures(ALICE);
    let other_home = setup_test_keystore_from_fixtures(ALICE);
    let key_ctx = KeyContext::from_inner(setup_member_key_context(&key_home, ALICE, None));

    let local_state = LocalStateSession::open(other_home.path().to_path_buf()).unwrap();
    let error = TrustCommandSession::open(&local_state, member_handle(ALICE), key_ctx)
        .err()
        .expect("a different home capability must be rejected");

    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
}

#[test]
fn test_trust_command_session_fixes_created_trust_directory() {
    let home = setup_test_keystore_from_fixtures(ALICE);
    let key_ctx = KeyContext::from_inner(setup_member_key_context(&home, ALICE, None));
    let session = TrustCommandSession::from_test_parts(home.path(), member_handle(ALICE), key_ctx)
        .expect("bind trust command session");

    assert!(session.trust_dir().is_none());
    let first = session
        .ensured_trust_directory()
        .expect("create trust directory");
    let second = session
        .ensured_trust_directory()
        .expect("reuse trust directory");

    assert!(Arc::ptr_eq(first, second));
    assert!(Arc::ptr_eq(
        first,
        session.trust_dir().expect("fixed trust directory")
    ));
}
