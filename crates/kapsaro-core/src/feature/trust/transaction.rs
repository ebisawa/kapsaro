// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! The two halves of a local trust store update: observe, then commit.
//! Keeps the trust and member locks apart by reading the signer key first.

use crate::feature::trust::signer_keys::{document_signer_kid, SignerKeySnapshot};
use crate::feature::trust::store_mutation::{
    build_empty_trust_store, build_trust_store_not_found_error, resolve_trust_store_write,
    save_resolved_trust_store_at, TrustStoreMutation, TrustStoreMutationMode,
    TrustStoreMutationOutcome, TrustStoreMutationTarget, TrustStoreState,
};
use crate::feature::trust::verification::verify_trust_store;
use crate::io::keystore::access::KeystoreAccess;
use crate::io::trust::store::{
    attach_trust_store_recovery, build_trust_store_conflict_error,
    load_trust_store_with_shared_lock, with_exclusive_trust_store_load, TrustStoreLoadResult,
    TrustStoreSnapshot,
};
use crate::model::identity::{Kid, MemberHandle};
use crate::model::trust_store::{TrustStoreDocument, TrustStoreProtected};
use crate::model::trust_store_verified::VerifiedTrustStore;
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::lock::{ExclusiveLockedDir, LockTargetDirectory};
use crate::support::fs::relative::DirectoryFd;
use crate::{Error, Result};
use std::fmt;
use std::path::Path;

/// A stored trust store that verified against the owner's keys.
pub(crate) struct VerifiedStoredTrustStore {
    pub(crate) protected: TrustStoreProtected,
    /// Key named by the signature the stored document carried.
    pub(crate) signer_kid: Kid,
}

/// The keystore one verification runs against: the caller's, or one opened
/// for the occasion.
///
/// Borrowing keeps a caller's own keystore from being reopened; a caller with
/// none falls back to the owner's local one, which this then owns.
pub(crate) enum OwnerKeystore<'a> {
    Borrowed(&'a KeystoreAccess),
    Owned(KeystoreAccess),
}

impl OwnerKeystore<'_> {
    pub(crate) fn as_ref(&self) -> &KeystoreAccess {
        match self {
            Self::Borrowed(keystore) => keystore,
            Self::Owned(keystore) => keystore,
        }
    }
}

/// Use the keystore a caller already opened, or open the owner's local one.
///
/// A read that never resolved a keystore of its own still has to verify
/// against something, and the owner's local keystore under `base` is the one
/// every such caller falls back to the same way.
pub(crate) fn resolve_owner_keystore<'a>(
    keystore: Option<&'a KeystoreAccess>,
    base: &AnchoredDir,
    owner: &MemberHandle,
) -> Result<OwnerKeystore<'a>> {
    match keystore {
        Some(keystore) => Ok(OwnerKeystore::Borrowed(keystore)),
        None => {
            KeystoreAccess::open_from_anchored_home_required(base, owner).map(OwnerKeystore::Owned)
        }
    }
}

/// What one commit binds itself to: steps 1 and 3 of the transaction.
///
/// The bytes and the signer key are taken under two separate shared locks,
/// each released before the next is acquired, so the exclusive commit that
/// follows holds neither of them.
///
/// The keystore the keys were read from travels along, because a merged write
/// that finds the bytes moved has to read the key the new bytes name before it
/// can take the exclusive lock again.
pub(crate) struct TrustStorePreparation {
    snapshot: TrustStoreSnapshot,
    signer_keys: SignerKeySnapshot,
    keystore: KeystoreAccess,
}

/// Report what the commit is bound to, and nothing about where it came from.
///
/// The snapshot and the signer key are what a commit turns on. The keystore is
/// only the capability the re-observation reads through, and writing it would
/// replay a local path into every enclosing type's `{:?}`.
impl fmt::Debug for TrustStorePreparation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustStorePreparation")
            .field("snapshot", &self.snapshot)
            .field("signer_keys", &self.signer_keys)
            .finish_non_exhaustive()
    }
}

/// A preparation together with the content it observed and verified.
pub(crate) struct ObservedTrustStore {
    prepared: TrustStorePreparation,
    stored: Option<VerifiedStoredTrustStore>,
}

/// What the commit has to establish about the stored document before mutating.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TrustStoreCommitGate {
    /// The stored bytes must still be exactly the ones that were observed.
    ///
    /// A caller that showed a person the content it decided on binds itself
    /// here: bytes that moved are the operator's to look at again, so the write
    /// stops as a conflict rather than landing on something nobody reviewed.
    ReviewedContent,
    /// Whatever is stored when the write lands is taken and merged into.
    ///
    /// The commit still only writes over content its own observation saw, but
    /// bytes that moved are observed again instead of being reported: the key
    /// the new document names is read under the member lock, and the exclusive
    /// lock is taken afresh. So a store another writer created, or re-signed
    /// with a rotated key, is merged into rather than costing this approval.
    LatestContent,
}

impl TrustStorePreparation {
    /// Bind a commit to bytes observed earlier, with the keys read now.
    ///
    /// Step 3 still runs here, so the commit verifies against keys read under a
    /// member lock this call has already released.
    ///
    /// `signer_kid` names the key the reviewed content was signed with. The
    /// gate accepts nothing but that content, so this is the only key the
    /// commit can need; a reviewed absence names none.
    pub(crate) fn from_reviewed_snapshot(
        snapshot: TrustStoreSnapshot,
        signer_kid: Option<&Kid>,
        keystore: &KeystoreAccess,
        owner: &MemberHandle,
    ) -> Result<Self> {
        SignerKeySnapshot::capture(keystore, owner, signer_kid).map(|signer_keys| Self {
            snapshot,
            signer_keys,
            keystore: keystore.clone(),
        })
    }

    /// Read the stored bytes, then the key their signature names.
    ///
    /// The trust directory's shared lock is released before the keystore is
    /// consulted, so neither lock is held while the other is taken. The
    /// document read under that lock is handed back so a caller that also has
    /// to verify it does not read it a second time.
    fn observe<D>(
        base: &AnchoredDir,
        trust_dir: &D,
        path: &Path,
        owner: &MemberHandle,
        keystore: &KeystoreAccess,
    ) -> Result<(Self, Option<TrustStoreLoadResult>)>
    where
        D: DirectoryFd + LockTargetDirectory,
    {
        let loaded = load_trust_store_with_shared_lock(base, trust_dir, path)?;
        let signer_kid = loaded
            .as_ref()
            .and_then(|loaded| document_signer_kid(&loaded.document));
        let signer_keys = SignerKeySnapshot::capture(keystore, owner, signer_kid.as_ref())?;
        let prepared = Self {
            snapshot: TrustStoreSnapshot::from_loaded(loaded.as_ref()),
            signer_keys,
            keystore: keystore.clone(),
        };
        Ok((prepared, loaded))
    }

    /// Observe the store this mutation targets again, keeping the same keystore.
    fn reobserve(&self, target: &TrustStoreMutationTarget<'_>) -> Result<Self> {
        Self::observe(
            target.base,
            target.trust_dir,
            target.path,
            target.owner,
            &self.keystore,
        )
        .map(|(prepared, _)| prepared)
    }
}

impl ObservedTrustStore {
    /// Run steps 1 to 4: observe the stored bytes, read the key, verify.
    pub(crate) fn observe<D>(
        base: &AnchoredDir,
        trust_dir: &D,
        path: &Path,
        owner: &MemberHandle,
        keystore: &KeystoreAccess,
    ) -> Result<Self>
    where
        D: DirectoryFd + LockTargetDirectory,
    {
        let (prepared, loaded) =
            TrustStorePreparation::observe(base, trust_dir, path, owner, keystore)?;
        let stored = loaded
            .map(|loaded| verify_stored_trust_store(loaded, &prepared.signer_keys))
            .transpose()?;
        Ok(Self { prepared, stored })
    }

    pub(crate) fn prepared(&self) -> &TrustStorePreparation {
        &self.prepared
    }

    /// The stored content, when there was a document to verify.
    pub(crate) fn stored(&self) -> Option<&VerifiedStoredTrustStore> {
        self.stored.as_ref()
    }

    pub(crate) fn into_prepared(self) -> TrustStorePreparation {
        self.prepared
    }
}

impl From<VerifiedStoredTrustStore> for TrustStoreState {
    fn from(stored: VerifiedStoredTrustStore) -> Self {
        Self {
            protected: stored.protected,
            signer_kid: Some(stored.signer_kid),
        }
    }
}

/// Verify one trust store document against the owner's keys.
pub(crate) fn verify_trust_store_with_owner_keys(
    doc: &TrustStoreDocument,
    keystore: &KeystoreAccess,
    owner: &MemberHandle,
) -> Result<VerifiedTrustStore> {
    let signer_keys =
        SignerKeySnapshot::capture(keystore, owner, document_signer_kid(doc).as_ref())?;
    verify_trust_store(doc, &signer_keys)
}

/// Run steps 5 and 6: take the exclusive lock, then mutate and persist.
///
/// What `gate` decides is what content that is not the content this commit is
/// bound to means: whether bytes that moved are reported or observed again and
/// merged into, and what a store that no longer reads back at all is called.
/// A reviewed write calls it a conflict either way, which keeps
/// `E_TRUST_STORE_RESET_REQUIRED` out of a write-back the operator only has to
/// run again, and with it the offer to delete their approvals. A merged write
/// has no reviewed content to hold against, so it reports the store as what it
/// is and names the route back.
///
/// The signer key was read before the trust lock was taken and nothing reaches
/// for the keystore once that lock is held, so a key another process removes in
/// between goes unnoticed here: the commit signs with the key it already holds.
/// The stored document can therefore end up naming a `signature.kid` the
/// keystore no longer has, and the next load reports that as a signer key that
/// is unavailable, carrying the route back with it.
pub(crate) fn commit_trust_store_mutation<T, F>(
    target: &TrustStoreMutationTarget<'_>,
    prepared: &TrustStorePreparation,
    gate: TrustStoreCommitGate,
    mutate: F,
) -> Result<TrustStoreMutationOutcome<T>>
where
    F: FnOnce(&mut TrustStoreProtected) -> Result<TrustStoreMutation<T>>,
{
    match gate {
        TrustStoreCommitGate::ReviewedContent => {
            match commit_bound_trust_store_mutation(target, prepared, mutate)? {
                TrustStoreCommitAttempt::Committed(outcome) => Ok(outcome),
                TrustStoreCommitAttempt::Stale(_) | TrustStoreCommitAttempt::Unusable(_) => {
                    Err(build_trust_store_conflict_error())
                }
            }
        }
        TrustStoreCommitGate::LatestContent => {
            commit_merged_trust_store_mutation(target, prepared, mutate)
        }
    }
}

/// How many times a merged write re-observes before it gives up.
///
/// Every re-observation answers one other writer that committed in between, so
/// the limit only bites under contention no single run can outlast. Reaching it
/// is reported as a conflict rather than retried forever.
const MERGED_OBSERVATION_LIMIT: usize = 8;

/// Commit a merged write, re-observing whenever the stored content moved.
///
/// The commit verifies with a key read before the trust lock was taken, so it
/// can only accept content the observation it is bound to actually saw. Content
/// another writer left behind is therefore observed again -- its bytes under
/// the trust directory's shared lock, then the key its signature names under
/// the member lock, each released before the next is taken -- and the exclusive
/// lock is acquired afresh. That is what lets a store another writer created,
/// or re-signed with a rotated key, be merged into rather than lost.
///
/// A store that no longer reads back is not content that moved. Nothing this
/// write could observe would make it usable, so it is reported as the store it
/// is, with the route back, instead of as a conflict the operator re-runs into.
fn commit_merged_trust_store_mutation<T, F>(
    target: &TrustStoreMutationTarget<'_>,
    prepared: &TrustStorePreparation,
    mut mutate: F,
) -> Result<TrustStoreMutationOutcome<T>>
where
    F: FnOnce(&mut TrustStoreProtected) -> Result<TrustStoreMutation<T>>,
{
    let mut reobserved: Option<TrustStorePreparation> = None;
    for attempt in 0..MERGED_OBSERVATION_LIMIT {
        let bound = reobserved.as_ref().unwrap_or(prepared);
        match commit_bound_trust_store_mutation(target, bound, mutate)? {
            TrustStoreCommitAttempt::Committed(outcome) => return Ok(outcome),
            TrustStoreCommitAttempt::Unusable(error) => {
                return Err(attach_trust_store_recovery(target.path, error))
            }
            TrustStoreCommitAttempt::Stale(unused) => mutate = unused,
        }
        if !stale_attempt_leaves_room_to_reobserve(attempt) {
            break;
        }
        let next = bound.reobserve(target)?;
        reobserved = Some(next);
    }
    Err(build_trust_store_conflict_error())
}

/// Whether an attempt that found the content moved has an attempt left for what
/// observing it again would find.
///
/// One observation costs the trust directory's shared lock, a trust store read
/// and a keystore read, and no attempt follows the last one. Taking it would
/// spend all three on content nothing goes on to commit against, and a failure
/// of that read would be reported in place of the conflict the run has already
/// established.
fn stale_attempt_leaves_room_to_reobserve(attempt: usize) -> bool {
    attempt + 1 < MERGED_OBSERVATION_LIMIT
}

/// What one attempt at the exclusive commit came back with.
enum TrustStoreCommitAttempt<T, F> {
    /// The write ran against the content the attempt was bound to.
    Committed(TrustStoreMutationOutcome<T>),
    /// The stored content had moved, so the mutation comes back unused.
    Stale(F),
    /// The stored content read back as something no commit can run against.
    Unusable(Error),
}

/// Take the exclusive lock and write, when the stored content is still the one
/// `prepared` observed.
///
/// A mutation the lock refuses is handed back rather than run, so the caller
/// decides what the content it found means: a reviewed write reports content
/// that moved, a merged one observes it again and comes back, and a store that
/// no longer reads back is the caller's to name either way.
fn commit_bound_trust_store_mutation<T, F>(
    target: &TrustStoreMutationTarget<'_>,
    prepared: &TrustStorePreparation,
    mutate: F,
) -> Result<TrustStoreCommitAttempt<T, F>>
where
    F: FnOnce(&mut TrustStoreProtected) -> Result<TrustStoreMutation<T>>,
{
    with_exclusive_trust_store_load(
        target.base,
        target.trust_dir,
        target.path,
        |locked_trust_dir, loaded| {
            let content = resolve_locked_trust_store_content(target, prepared, loaded)?;
            match content {
                LockedTrustStoreContent::Moved => Ok(TrustStoreCommitAttempt::Stale(mutate)),
                LockedTrustStoreContent::Unusable(error) => {
                    Ok(TrustStoreCommitAttempt::Unusable(error))
                }
                LockedTrustStoreContent::Usable(state) => {
                    apply_and_save_trust_store(target, locked_trust_dir, state, mutate)
                        .map(TrustStoreCommitAttempt::Committed)
                }
            }
        },
    )
}

/// What the exclusive lock found, before anything decides what it means.
enum LockedTrustStoreContent {
    /// Content the mutation can run against, verified under the lock.
    Usable(TrustStoreState),
    /// Bytes other than the ones the commit is bound to.
    Moved,
    /// Bytes that read back as something no commit can run against.
    Unusable(Error),
}

/// Read what the exclusive lock settled on, keeping the mutation out of it.
///
/// Nothing here reports anything: the mutation stays with the caller so it is
/// never run against content this has not accepted, and the gate is what turns
/// content that moved or will not read back into a message.
fn resolve_locked_trust_store_content(
    target: &TrustStoreMutationTarget<'_>,
    prepared: &TrustStorePreparation,
    loaded: Result<Option<TrustStoreLoadResult>>,
) -> Result<LockedTrustStoreContent> {
    let loaded = match loaded {
        Ok(loaded) => loaded,
        Err(error) => return classify_locked_failure(error),
    };
    if TrustStoreSnapshot::from_loaded(loaded.as_ref()) != prepared.snapshot {
        return Ok(LockedTrustStoreContent::Moved);
    }
    build_trust_store_for_commit(target, prepared, loaded)
}

/// Apply the mutation to the content the lock settled on and persist it.
fn apply_and_save_trust_store<T, F>(
    target: &TrustStoreMutationTarget<'_>,
    locked_trust_dir: &ExclusiveLockedDir<'_>,
    state: TrustStoreState,
    mutate: F,
) -> Result<TrustStoreMutationOutcome<T>>
where
    F: FnOnce(&mut TrustStoreProtected) -> Result<TrustStoreMutation<T>>,
{
    let previous_signer_kid = state.signer_kid;
    let mut protected = state.protected;
    let mutation = mutate(&mut protected)?;
    let write = resolve_trust_store_write(
        mutation.changed,
        previous_signer_kid.as_ref().map(Kid::as_str),
        target.signing.signer_kid(),
    );
    save_resolved_trust_store_at(
        target.base,
        locked_trust_dir,
        target.path,
        &mut protected,
        target.signing,
        write,
    )?;
    Ok(TrustStoreMutationOutcome {
        value: mutation.value,
        write,
        signer_kid: target.signing.signer_kid().to_string(),
    })
}

/// Resolve the content this mutation runs against, verified under the lock.
fn build_trust_store_for_commit(
    target: &TrustStoreMutationTarget<'_>,
    prepared: &TrustStorePreparation,
    loaded: Option<TrustStoreLoadResult>,
) -> Result<LockedTrustStoreContent> {
    match (target.mode, loaded) {
        (_, Some(loaded)) => match verify_stored_trust_store(loaded, &prepared.signer_keys) {
            Ok(stored) => Ok(LockedTrustStoreContent::Usable(stored.into())),
            Err(error) => classify_locked_failure(error),
        },
        (TrustStoreMutationMode::CreateIfMissing, None) => {
            build_empty_trust_store(target.owner).map(LockedTrustStoreContent::Usable)
        }
        (TrustStoreMutationMode::ExistingRequired, None) => {
            Err(build_trust_store_not_found_error(target.owner.as_str()))
        }
    }
}

/// Report a failure met under the exclusive lock the way its cause allows.
///
/// A failure that reads the stored bytes is a statement about them, so it comes
/// back as content no commit can run against and the gate decides what to call
/// it. An I/O failure or an unsafe path says nothing about the content and
/// travels as itself.
fn classify_locked_failure(error: Error) -> Result<LockedTrustStoreContent> {
    if error.kind().is_content_failure() {
        Ok(LockedTrustStoreContent::Unusable(error))
    } else {
        Err(error)
    }
}

fn verify_stored_trust_store(
    loaded: TrustStoreLoadResult,
    signer_keys: &SignerKeySnapshot,
) -> Result<VerifiedStoredTrustStore> {
    let verified = verify_trust_store(&loaded.document, signer_keys)?;
    let (doc, _) = verified.into_inner();
    let signer_kid = Kid::from_canonical(doc.signature.kid.clone())?;
    Ok(VerifiedStoredTrustStore {
        protected: doc.protected,
        signer_kid,
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_trust_transaction_test.rs"]
mod tests;
