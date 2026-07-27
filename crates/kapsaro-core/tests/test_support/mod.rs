// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Common test utilities for environment variable management

// Shared helper sources from kapsaro-test-support, included via #[path] so they
// compile within kapsaro-core's test binaries and keep type identity with crate:: paths.
#[path = "../../../kapsaro-test-support/src/constants.rs"]
#[allow(dead_code)]
mod constants;
#[path = "../../../kapsaro-test-support/src/crypto_context.rs"]
pub mod crypto_context;
#[path = "../../../kapsaro-test-support/src/ed25519_backend.rs"]
pub mod ed25519_backend;
#[path = "../../../kapsaro-test-support/src/fixture.rs"]
mod fixture;
#[path = "../../../kapsaro-test-support/src/guards.rs"]
pub mod guards;
#[path = "../../../kapsaro-test-support/src/keygen_helpers.rs"]
#[allow(dead_code)]
pub mod keygen_helpers;
#[path = "ssh_stubs.rs"]
#[allow(dead_code)]
mod ssh_stubs;
#[path = "../../../kapsaro-test-support/src/workspace_state.rs"]
#[allow(dead_code)]
pub mod workspace_state;
#[allow(unused_imports)]
pub use constants::{
    ALICE_MEMBER_HANDLE, BOB_MEMBER_HANDLE, CAROL_MEMBER_HANDLE, DAVE_MEMBER_HANDLE,
    TEST_MEMBER_HANDLE,
};
#[allow(unused_imports)]
pub use crypto_context::setup_member_key_context;
#[allow(unused_imports)]
pub use fixture::{
    generate_temp_ssh_keypair_in_dir, load_fixture_ssh_pubkey, save_public_key,
    setup_test_keystore, setup_test_keystore_from_fixtures, setup_test_workspace,
    setup_test_workspace_from_fixtures,
};
#[allow(unused_imports)]
pub use guards::{with_temp_cwd, EnvGuard};
#[allow(unused_imports)]
pub use keygen_helpers::{build_test_private_key, keygen_test};
#[allow(unused_imports)]
pub use ssh_stubs::stub_agent_signer;
#[allow(unused_imports)]
pub use workspace_state::{
    build_expiring_soon_timestamp, kid, member_handle, save_active_public_key_to_workspace,
    save_active_public_key_to_workspace_incoming, setup_trust_store_for_workspace,
    update_active_private_key_expires_at,
};

#[allow(dead_code)]
pub fn error_chain_contains_serde_json(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = error.source();
    while let Some(source) = current {
        if source.downcast_ref::<serde_json::Error>().is_some() {
            return true;
        }
        current = source.source();
    }
    false
}
