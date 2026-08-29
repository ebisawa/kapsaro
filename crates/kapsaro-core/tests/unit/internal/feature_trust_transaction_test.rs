// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests how a commit reports the failures it can meet under the trust lock.
//! Separates content that moved from a store that no longer reads back at all.

use super::{
    classify_locked_failure, commit_trust_store_mutation, stale_attempt_leaves_room_to_reobserve,
    LockedTrustStoreContent, ObservedTrustStore, TrustStoreCommitGate, MERGED_OBSERVATION_LIMIT,
};
use crate::app_test_utils::save_test_trust_store_signed_by_active_key;
use crate::error::{LOCAL_STATE_PATH_UNSAFE_RECOVERY, TRUST_STORE_RESET_REQUIRED_RECOVERY};
use crate::feature::context::crypto::{build_signing_context, VerifiedSigningContext};
use crate::feature::trust::store_mutation::{
    TrustStoreMutation, TrustStoreMutationMode, TrustStoreMutationTarget,
};
use crate::io::keystore::access::KeystoreAccess;
use crate::io::trust::paths::get_trust_store_file_path;
use crate::model::identity::MemberHandle;
use crate::model::trust_store::TrustStoreProtected;
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::relative::{open_optional_child_dir, DirectoryScope, OpenDir};
use crate::test_utils::{
    member_handle, setup_member_key_context, setup_test_keystore_from_fixtures,
};
use crate::{Error, ErrorKind, Result};
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

const OWNER: &str = "alice@example.com";
const STORED_AT: &str = "2026-03-29T12:34:56Z";

/// One stored trust store together with the capabilities a commit writes
/// through, each opened the way the transaction opens it.
struct TrustStoreFixture {
    base: AnchoredDir,
    trust_dir: OpenDir,
    path: PathBuf,
    owner: MemberHandle,
    keystore: KeystoreAccess,
}

impl TrustStoreFixture {
    /// Stage a trust store that verifies, and open what a commit needs.
    fn new(home: &TempDir) -> Self {
        save_test_trust_store_signed_by_active_key(home, OWNER, STORED_AT);
        let base = AnchoredDir::open(
            home.path(),
            DirectoryScope::LocalState,
            "test local state root",
        )
        .expect("open test local state root");
        let trust_dir = open_optional_child_dir(&base, "trust")
            .expect("open trust directory")
            .expect("the staged store created the trust directory");
        let owner = member_handle(OWNER);
        let path = get_trust_store_file_path(home.path(), &owner);
        let keystore = KeystoreAccess::open_from_anchored_home_required(&base, &owner)
            .expect("open the owner's keystore");
        Self {
            base,
            trust_dir,
            path,
            owner,
            keystore,
        }
    }

    /// Run steps 1 to 4 against the staged store.
    fn observe(&self) -> ObservedTrustStore {
        ObservedTrustStore::observe(
            &self.base,
            &self.trust_dir,
            &self.path,
            &self.owner,
            &self.keystore,
        )
        .expect("the staged trust store verifies")
    }

    fn target<'a>(
        &'a self,
        signing: &'a VerifiedSigningContext<'a>,
    ) -> TrustStoreMutationTarget<'a> {
        TrustStoreMutationTarget {
            base: &self.base,
            trust_dir: &self.trust_dir,
            path: &self.path,
            owner: &self.owner,
            mode: TrustStoreMutationMode::ExistingRequired,
            signing,
        }
    }

    /// Leave bytes behind that no reader can parse, as an interrupted write or
    /// a damaged file system would.
    fn break_stored_bytes(&self) {
        fs::write(&self.path, b"{ not a trust store").expect("replace the stored trust store");
    }
}

fn unchanged_mutation(_protected: &mut TrustStoreProtected) -> Result<TrustStoreMutation<()>> {
    Ok(TrustStoreMutation {
        value: (),
        changed: false,
    })
}

/// A store that broke between the observation and the exclusive lock is not
/// content that moved. Running the command again finds the same broken store,
/// so the merged write reports it as the store it is and names the route back
/// instead of asking for a re-run that cannot succeed.
#[test]
fn test_merged_commit_reports_a_store_that_broke_after_the_observation() {
    let home = setup_test_keystore_from_fixtures(OWNER);
    let fixture = TrustStoreFixture::new(&home);
    let key_ctx = setup_member_key_context(&home, OWNER, None);
    let signing = build_signing_context(&key_ctx).expect("build the signing context");
    let observed = fixture.observe();
    fixture.break_stored_bytes();

    let error = match commit_trust_store_mutation(
        &fixture.target(&signing),
        observed.prepared(),
        TrustStoreCommitGate::LatestContent,
        unchanged_mutation,
    ) {
        Ok(_) => panic!("a trust store that no longer reads back must not commit"),
        Err(error) => error,
    };

    assert_eq!(error.recovery(), Some(TRUST_STORE_RESET_REQUIRED_RECOVERY));
    assert!(
        !error
            .format_user_message()
            .contains("Run the command again"),
        "got: {}",
        error.format_user_message()
    );
}

/// A reviewed write reports the same store as content that moved. The caller
/// showed a person the content it decided on, and a write-back is not where the
/// operator is offered the deletion of their approvals.
#[test]
fn test_reviewed_commit_reports_a_broken_store_as_a_conflict() {
    let home = setup_test_keystore_from_fixtures(OWNER);
    let fixture = TrustStoreFixture::new(&home);
    let key_ctx = setup_member_key_context(&home, OWNER, None);
    let signing = build_signing_context(&key_ctx).expect("build the signing context");
    let observed = fixture.observe();
    fixture.break_stored_bytes();

    let error = match commit_trust_store_mutation(
        &fixture.target(&signing),
        observed.prepared(),
        TrustStoreCommitGate::ReviewedContent,
        unchanged_mutation,
    ) {
        Ok(_) => panic!("a trust store that no longer reads back must not commit"),
        Err(error) => error,
    };

    assert_eq!(error.kind(), ErrorKind::InvalidOperation);
    assert_eq!(error.recovery(), None);
    assert!(
        error
            .format_user_message()
            .contains("Run the command again"),
        "got: {}",
        error.format_user_message()
    );
}

/// One merged commit observes exactly as many times as it attempts: once before
/// the first attempt, and once after every attempt that has another attempt to
/// spend what it reads on. The attempt after the last one never runs, so the
/// observation that would feed it is never taken.
#[test]
fn test_the_final_attempt_does_not_spend_another_observation() {
    let reobservations = (0..MERGED_OBSERVATION_LIMIT)
        .filter(|attempt| stale_attempt_leaves_room_to_reobserve(*attempt))
        .count();

    assert!(stale_attempt_leaves_room_to_reobserve(
        MERGED_OBSERVATION_LIMIT - 2
    ));
    assert!(!stale_attempt_leaves_room_to_reobserve(
        MERGED_OBSERVATION_LIMIT - 1
    ));
    assert_eq!(reobservations, MERGED_OBSERVATION_LIMIT - 1);
}

/// Bytes that will not parse are a statement about the stored content, so they
/// come back for the gate to report rather than being named here.
#[test]
fn test_unparsable_content_under_the_lock_comes_back_for_the_gate() {
    let classified = classify_locked_failure(Error::build_parse_error(
        "Trust store is not valid JSON".to_string(),
    ));

    match classified {
        Ok(LockedTrustStoreContent::Unusable(error)) => assert_eq!(error.kind(), ErrorKind::Parse),
        _ => panic!("content that will not read back is the gate's to report"),
    }
}

/// The same for a document that read back and did not verify.
#[test]
fn test_unverifiable_content_under_the_lock_comes_back_for_the_gate() {
    let classified = classify_locked_failure(Error::build_verification_error(
        "E_TRUST_SIGNATURE_INVALID".to_string(),
        "Trust store signature verification failed".to_string(),
    ));

    match classified {
        Ok(LockedTrustStoreContent::Unusable(error)) => assert_eq!(error.kind(), ErrorKind::Verify),
        _ => panic!("a document that did not verify is the gate's to report"),
    }
}

/// An I/O failure says nothing about what the stored bytes hold, so no gate
/// gets to call it content that moved or a store that must be reset.
#[test]
fn test_io_failure_under_the_lock_is_reported_as_itself() {
    match classify_locked_failure(Error::build_io_error("Disk read failed")) {
        Err(error) => {
            assert_eq!(error.kind(), ErrorKind::Io);
            assert_eq!(error.format_user_message(), "Disk read failed");
        }
        Ok(_) => panic!("an I/O failure is not a statement about the stored content"),
    }
}

#[test]
fn test_unsafe_local_state_path_under_the_lock_is_reported_as_itself() {
    match classify_locked_failure(Error::build_local_state_path_unsafe_error(
        "Local trust directory is a symlink".to_string(),
    )) {
        Err(error) => {
            assert_eq!(error.recovery(), Some(LOCAL_STATE_PATH_UNSAFE_RECOVERY));
            assert!(error
                .format_user_message()
                .contains("Local trust directory is a symlink"));
        }
        Ok(_) => panic!("an unsafe path is not a statement about the stored content"),
    }
}
