// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for the guard that protects the trust store signature from a removal.
//! Fixes what a hand-over leaves behind when it turns out it cannot complete.

use std::path::Path;

use crate::api::key::KeyContext;
use crate::app_test_utils::{
    add_generated_key, load_test_trust_store, rotate_active_key,
    save_test_trust_store_signed_by_active_key, TestCommandOptions,
};
use crate::error::TRUST_SIGNER_KEY_IN_USE_RECOVERY;
use crate::io::trust::paths::get_trust_store_file_path;
use crate::io::trust::store::fail_next_trust_store_save;
use crate::model::identity::{Kid, MemberHandle};
use crate::service::key::manage::remove_key_command;
use crate::service::key::types::KeyRemoveResult;
use crate::service::trust::TrustCommandSession;
use crate::test_utils::{
    kid, member_handle, setup_member_key_context, setup_test_keystore_from_fixtures,
    ALICE_MEMBER_HANDLE,
};
use tempfile::TempDir;

const STORED_AT: &str = "2026-03-29T12:34:56Z";
const SIGNING_FAILURE: &str = "ssh-agent is not reachable";
const UNREADABLE_STORE_FAILURE: &str = "the trust store could not be opened";
const REMOVED_KID: &str = "7M2Q9D4R1H8VW6PKT3XNC5JY2F9AR8GD";

fn build_options(home: &Path) -> TestCommandOptions {
    TestCommandOptions::new().with_home(Some(home.to_path_buf()))
}

/// Signing identity a hand-over is given, bound to one key of the owner.
fn signing_session(home: &TempDir, kid: Option<&str>) -> TrustCommandSession {
    TrustCommandSession::from_test_parts(
        home.path(),
        MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap(),
        KeyContext::from_inner(setup_member_key_context(home, ALICE_MEMBER_HANDLE, kid)),
    )
    .unwrap()
}

/// Replace the stored trust store with one signed by the key `kid` names.
///
/// This is what another process re-signing the store looks like from here: the
/// document verifies, and the key its signature names is not the one the
/// removal was classified against.
fn resign_stored_trust_store_with(home: &TempDir, kid: &Kid) {
    use crate::feature::trust::signature::sign_trust_store;
    use crate::model::trust_store::TrustStoreProtected;
    use crate::model::wire::format::LOCAL_TRUST_V1;
    use crate::test_support::storage::trust::store::save_trust_store;

    let key_ctx = setup_member_key_context(home, ALICE_MEMBER_HANDLE, Some(kid.as_str()));
    let protected = TrustStoreProtected {
        format: LOCAL_TRUST_V1.to_string(),
        owner_handle: ALICE_MEMBER_HANDLE.to_string(),
        created_at: STORED_AT.to_string(),
        updated_at: STORED_AT.to_string(),
        known_keys: Vec::new(),
        recipient_sets: Vec::new(),
    };
    let document = sign_trust_store(&protected, key_ctx.signing_key(), key_ctx.kid()).unwrap();
    save_trust_store(
        &get_trust_store_file_path(home.path(), &member_handle(ALICE_MEMBER_HANDLE)),
        &document,
    )
    .unwrap();
}

fn stored_signer_kid(options: &TestCommandOptions) -> String {
    load_test_trust_store(options, ALICE_MEMBER_HANDLE)
        .unwrap()
        .expect("the stored trust store must still verify")
        .signer_kid
        .expect("a verified store names its signer")
        .into_string()
}

fn key_dir(home: &TempDir, kid: &str) -> std::path::PathBuf {
    home.path().join("keys").join(ALICE_MEMBER_HANDLE).join(kid)
}

/// One removal of the store's signer key, with the store re-signed by a third
/// key in the window the signing identity is resolved in.
struct HandoverRace {
    home: TempDir,
    removed_kid: String,
    other_kid: Kid,
    active_kid: Kid,
}

impl HandoverRace {
    fn set_up() -> Self {
        let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
        let removed_kid =
            save_test_trust_store_signed_by_active_key(&home, ALICE_MEMBER_HANDLE, STORED_AT);
        let other_kid = add_generated_key(home.path(), ALICE_MEMBER_HANDLE);
        let active_kid = rotate_active_key(home.path(), ALICE_MEMBER_HANDLE);
        Self {
            home,
            removed_kid,
            other_kid,
            active_kid,
        }
    }

    fn remove_signer_key(&self, force: bool) -> crate::Result<KeyRemoveResult> {
        remove_key_command(
            self.home.path(),
            None,
            self.removed_kid.clone(),
            force,
            |_member_handle| {
                resign_stored_trust_store_with(&self.home, &self.other_kid);
                Ok(signing_session(&self.home, Some(self.active_kid.as_str())))
            },
        )
    }
}

/// One removal of the store's signer key whose hand-over is planned and then
/// stops on the write itself, which is what another writer taking the exclusive
/// lock and re-signing first looks like from here: the plan observed the removed
/// key as the signer, and the commit never came back to say where it ended up.
struct UncommittedHandover {
    home: TempDir,
    removed_kid: String,
    active_kid: Kid,
}

impl UncommittedHandover {
    fn set_up() -> Self {
        let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
        let removed_kid =
            save_test_trust_store_signed_by_active_key(&home, ALICE_MEMBER_HANDLE, STORED_AT);
        let active_kid = rotate_active_key(home.path(), ALICE_MEMBER_HANDLE);
        Self {
            home,
            removed_kid,
            active_kid,
        }
    }

    fn force_remove_signer_key(&self) -> crate::Result<KeyRemoveResult> {
        remove_key_command(
            self.home.path(),
            None,
            self.removed_kid.clone(),
            true,
            |_member_handle| {
                let execution = signing_session(&self.home, Some(self.active_kid.as_str()));
                fail_next_trust_store_save();
                Ok(execution)
            },
        )
    }
}

/// One removal of the store's signer key whose hand-over has no signing
/// identity to run with, which is what an absent ssh-agent looks like here.
struct UnsignableHandover {
    home: TempDir,
    removed_kid: String,
}

impl UnsignableHandover {
    fn set_up() -> Self {
        let home = setup_test_keystore_from_fixtures(ALICE_MEMBER_HANDLE);
        let removed_kid =
            save_test_trust_store_signed_by_active_key(&home, ALICE_MEMBER_HANDLE, STORED_AT);
        rotate_active_key(home.path(), ALICE_MEMBER_HANDLE);
        Self { home, removed_kid }
    }

    fn remove_signer_key(&self) -> crate::Result<KeyRemoveResult> {
        remove_key_command(
            self.home.path(),
            None,
            self.removed_kid.clone(),
            false,
            |_member_handle| Err(crate::Error::build_ssh_error(SIGNING_FAILURE)),
        )
    }
}

/// A hand-over the command could not even attempt is a decision this command
/// makes, not an SSH failure handed up untouched. The operator is told the
/// removal was stopped, what stopped it, and both ways past it.
#[test]
fn test_a_hand_over_that_cannot_sign_names_the_way_past_it() {
    let fixture = UnsignableHandover::set_up();
    let options = build_options(fixture.home.path());

    let error = fixture
        .remove_signer_key()
        .expect_err("a hand-over without a signing identity must stop the removal");

    assert_eq!(error.recovery(), Some(TRUST_SIGNER_KEY_IN_USE_RECOVERY));
    let message = error.format_user_message();
    assert!(message.contains(SIGNING_FAILURE), "{message}");
    assert!(
        message.contains("kapsaro key activate <other-kid> --member-handle alice@example.com"),
        "{message}"
    );
    assert!(message.contains("--force"), "{message}");
    assert_eq!(stored_signer_kid(&options), fixture.removed_kid);
    assert!(key_dir(&fixture.home, &fixture.removed_kid).exists());
}

/// A hand-over that cannot take the signature off the removed key is refused
/// before it writes. The stored signature stays exactly where the removal found
/// it, rather than being moved by a command that then fails, and the refusal
/// names the key that carries it now.
#[test]
fn test_a_refused_hand_over_leaves_the_stored_signature_alone() {
    let race = HandoverRace::set_up();
    let options = build_options(race.home.path());

    let error = race
        .remove_signer_key(false)
        .expect_err("a hand-over that cannot move the signature must stop the removal");

    let message = error.format_user_message();
    assert_eq!(error.kind(), crate::ErrorKind::InvalidOperation);
    assert!(message.contains("cannot complete"), "{message}");
    assert!(message.contains(race.other_kid.as_str()), "{message}");
    assert_eq!(stored_signer_kid(&options), race.other_kid.as_str());
    assert!(key_dir(&race.home, &race.removed_kid).exists());
}

/// A signature another process moved to a third key is still verifiable: that
/// key is one this member holds. The forced removal reports which key carries
/// the signature now and that the stored approvals verify under it, so the
/// operator is not sent to restore a key or reset an intact store.
#[test]
fn test_a_forced_removal_reports_the_key_that_carries_the_moved_signature() {
    let race = HandoverRace::set_up();
    let options = build_options(race.home.path());

    let result = race
        .remove_signer_key(true)
        .expect("a forced removal goes on once the moved signature is reported");

    assert!(result.resigned_trust_store_kid.is_none());
    let warning = result
        .trust_store_warning
        .expect("a hand-over that could not complete must be reported");
    assert!(warning.contains(race.other_kid.as_str()), "{warning}");
    assert!(warning.contains("still verify"), "{warning}");
    assert_eq!(stored_signer_kid(&options), race.other_kid.as_str());
    assert!(!key_dir(&race.home, &race.removed_kid).exists());
}

/// A hand-over whose write never came back settles nothing: it may have landed,
/// and another writer may have taken the signature to a key this member still
/// holds. The forced removal says the outcome was not established and names the
/// re-signing that settles it, rather than sending the operator to restore a
/// key for a store that may be intact.
#[test]
fn test_a_forced_removal_reports_an_unfinished_hand_over_as_unsettled() {
    let fixture = UncommittedHandover::set_up();

    let result = fixture
        .force_remove_signer_key()
        .expect("a forced removal goes on once the unfinished hand-over is reported");

    assert!(result.resigned_trust_store_kid.is_none());
    let warning = result
        .trust_store_warning
        .expect("a hand-over that could not complete must be reported");
    assert!(warning.contains(&fixture.removed_kid), "{warning}");
    assert!(warning.contains("was not established"), "{warning}");
    assert!(
        warning.contains("kapsaro trust resign --member-handle alice@example.com"),
        "{warning}"
    );
    assert!(!key_dir(&fixture.home, &fixture.removed_kid).exists());
}

/// A removal stopped by a trust store nothing could read is a decision this
/// command makes, not a bare read failure handed up: the operator is told the
/// key is still there and what `--force` would cost.
#[test]
fn test_a_stopped_removal_states_what_an_unreadable_store_left_behind() {
    let cause = crate::Error::build_io_error(UNREADABLE_STORE_FAILURE);

    let member_handle = MemberHandle::try_from(ALICE_MEMBER_HANDLE).unwrap();
    let error = super::build_unreadable_store_error(&member_handle, &kid(REMOVED_KID), cause);

    let message = error.format_user_message();
    assert_eq!(error.recovery(), Some(TRUST_SIGNER_KEY_IN_USE_RECOVERY));
    assert!(message.contains(UNREADABLE_STORE_FAILURE), "{message}");
    assert!(message.contains(REMOVED_KID), "{message}");
    assert!(message.contains("was not removed"), "{message}");
    assert!(message.contains("--force"), "{message}");
}
