// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Active key selection for one keystore member.
//! Reads and publishes the `active` marker and resolves which key it names.

use super::inspection::list_kids_in_verified_namespace;
use super::key_pair::{PrivateHalfCheck, StoredKeyPair};
use super::{
    ensure_member_namespace_safe, finish_member_mutation, key_not_found, KeystoreAccess,
    ACTIVE_FILE,
};
use crate::model::identity::{Kid, MemberHandle};
use crate::model::public_key::PublicKey;
use crate::support::fs::lock::{with_exclusive_locked_directory, ExclusiveLockedDir};
use crate::support::fs::permission::{collect_open_permission_violations, report_violations};
use crate::support::fs::relative::{self, regular_file_exists_at, DirectoryFd};
use crate::support::kid::resolve_unique_kid;
use crate::support::limits::MAX_ACTIVE_KID_FILE_SIZE;
use crate::support::path::format_finding_path;
use crate::support::post_write::{format_post_change_failure, CompletedChange};
use crate::{Error, Result};

#[cfg(test)]
#[path = "../../../../tests/unit/internal/keystore_access_active_test.rs"]
mod keystore_access_active_test;

impl KeystoreAccess {
    pub(crate) fn resolve_kid(&self, member: &MemberHandle, query: Option<&str>) -> Result<Kid> {
        let member_dir = self
            .open_member(member)?
            .ok_or_else(|| no_keys_found(member))?;
        self.resolve_kid_in_verified_namespace(&member_dir, member, query)
    }

    /// Resolve which key `query` names and read its published public half.
    ///
    /// Both operations stay bound to one opened member directory. A concurrent
    /// removal may produce a retryable read failure, while a published key
    /// directory is never replaced with different content.
    pub(crate) fn resolve_public_key(
        &self,
        member: &MemberHandle,
        query: Option<&str>,
    ) -> Result<(Kid, PublicKey)> {
        let member_dir = self
            .open_member(member)?
            .ok_or_else(|| no_keys_found(member))?;
        let kid = self.resolve_kid_in_verified_namespace(&member_dir, member, query)?;
        self.load_public_key_in_verified_namespace(&member_dir, member, &kid)
            .map(|public_key| (kid, public_key))
    }

    /// Settle which key `query` names, inspecting the member namespace on the
    /// way.
    ///
    /// Every route out of here walks the member directory through the namespace
    /// check, so a caller may go on with the `*_in_verified_namespace` readers
    /// once this has answered.
    pub(super) fn resolve_kid_in_verified_namespace<D>(
        &self,
        member_dir: &D,
        member: &MemberHandle,
        query: Option<&str>,
    ) -> Result<Kid>
    where
        D: DirectoryFd,
    {
        if let Some(query) = query {
            let kids = list_kids_in_verified_namespace(member_dir)?;
            let resolved = resolve_unique_kid(kids.iter().map(Kid::as_str), query)?;
            return Kid::try_from(resolved);
        }
        if let Some(active) = self.load_active_kid_checked(member_dir)? {
            return Ok(active);
        }
        self.select_most_recent_kid(member_dir, member)
    }

    pub(crate) fn load_active_kid(&self, member: &MemberHandle) -> Result<Option<Kid>> {
        let Some(member_dir) = self.open_member(member)? else {
            return Ok(None);
        };
        self.load_active_kid_checked(&member_dir)
    }

    /// Point the active marker at one named key of `member`.
    ///
    /// The key has to meet what `activate_latest_valid_key` requires of the key
    /// it picks: both halves stored, readable as the key this directory names,
    /// and not expired. A marker naming anything less makes every read of the
    /// member's active key fail or report it as missing, which takes that
    /// member's signing, encryption and recipient resolution down while `key
    /// list` still shows the key.
    pub(crate) fn activate_existing_key(&self, member: &MemberHandle, kid: &Kid) -> Result<()> {
        let member_dir = self.open_member(member)?.ok_or_else(|| {
            Error::build_not_found_error(format!("Member '{}' not found", member))
        })?;
        with_exclusive_locked_directory(&member_dir, |locked_member_dir| {
            ensure_member_namespace_safe(locked_member_dir)?;
            let activability = self.inspect_key_activability(
                locked_member_dir,
                member,
                kid,
                time::OffsetDateTime::now_utc(),
                KeySelection::Activation,
            );
            let result = match activability {
                KeyActivability::Activatable(_) => save_active_kid_locked(locked_member_dir, kid),
                KeyActivability::Expired(_) => Err(expired_key_not_activatable(member, kid)),
                KeyActivability::Missing => Err(key_not_found(member, kid)),
                KeyActivability::HalfMissing => Err(half_missing_key_not_activatable(member, kid)),
                KeyActivability::Unreadable(error) => Err(error),
            };
            finish_member_mutation(
                locked_member_dir,
                &locked_member_dir.path().join(ACTIVE_FILE),
                CompletedChange::Written,
                result,
            )
        })
    }

    /// Activate the newest unexpired key of `member` that both halves exist for.
    ///
    /// Choosing and publishing happen under one exclusive lock, so the key the
    /// marker names is the key that was inspected. The whole selection and
    /// publication stays inside the writer's exclusive transaction.
    pub(crate) fn activate_latest_valid_key(&self, member: &MemberHandle) -> Result<Kid> {
        let member_dir = self
            .open_member(member)?
            .ok_or_else(|| no_keys_found(member))?;
        with_exclusive_locked_directory(&member_dir, |locked_member_dir| {
            ensure_member_namespace_safe(locked_member_dir)?;
            let result = self
                .select_activatable_kid_locked(locked_member_dir, member)
                .and_then(|kid| save_active_kid_locked(locked_member_dir, &kid).map(|()| kid));
            finish_member_mutation(
                locked_member_dir,
                &locked_member_dir.path().join(ACTIVE_FILE),
                CompletedChange::Written,
                result,
            )
        })
    }

    /// The newest unexpired key of `member` that both halves read back as.
    ///
    /// Ties on the creation timestamp, and keys stating no timestamp at all,
    /// are settled by the common ordering. A key whose documents cannot be read
    /// is passed over rather than failing the whole selection: this is the
    /// command the keystore names as the repair for a member left without an
    /// active key, so one unreadable key must not take that repair down with
    /// it. When nothing at all can be chosen, every such failure is reported.
    fn select_activatable_kid_locked(
        &self,
        member_dir: &ExclusiveLockedDir<'_>,
        member: &MemberHandle,
    ) -> Result<Kid> {
        let SelectableKeys {
            stored,
            candidates,
            half_missing,
            unreadable,
        } = self.collect_selectable_keys(member_dir, member, KeySelection::Activation)?;
        if stored == 0 {
            return Err(no_keys_found(member));
        }
        select_preferred_kid(candidates)
            .ok_or_else(|| no_activatable_key_found(member, &half_missing, &unreadable))
    }

    /// Inspect every key of `member` once and sort them into what may be
    /// selected and what each of the rest was ruled out by.
    ///
    /// Both walks come through here, so the ordering and the wording a key is
    /// ruled out with are the same on either. What `selection` decides is which
    /// keys are on offer at all: the question each walk answers is not the same
    /// one, so an expired key and a key whose private half will not open count
    /// differently between them.
    fn collect_selectable_keys<D>(
        &self,
        member_dir: &D,
        member: &MemberHandle,
        selection: KeySelection,
    ) -> Result<SelectableKeys>
    where
        D: DirectoryFd,
    {
        let now = time::OffsetDateTime::now_utc();
        let mut selectable = SelectableKeys::default();
        for kid in list_kids_in_verified_namespace(member_dir)? {
            selectable.stored += 1;
            match self.inspect_key_activability(member_dir, member, &kid, now, selection) {
                KeyActivability::Activatable(created_at) => {
                    selectable.candidates.push((kid, created_at))
                }
                KeyActivability::Expired(created_at) if selection.accepts_expired() => {
                    selectable.candidates.push((kid, created_at))
                }
                KeyActivability::Expired(_) => {}
                KeyActivability::Missing => {}
                KeyActivability::HalfMissing => selectable.half_missing.push(kid),
                KeyActivability::Unreadable(error) => selectable.unreadable.push(error),
            }
        }
        Ok(selectable)
    }

    /// Decide what one key of `member` is for the walk that is asking, and say
    /// what rules it out.
    ///
    /// The member namespace is inspected by the caller before it walks any key.
    ///
    /// A key that could not be read comes back carrying its own failure instead
    /// of ending the inspection, so a caller walking every key of a member
    /// decides for itself whether one unreadable key stops it.
    fn inspect_key_activability<D>(
        &self,
        member_dir: &D,
        member: &MemberHandle,
        kid: &Kid,
        now: time::OffsetDateTime,
        selection: KeySelection,
    ) -> KeyActivability
    where
        D: DirectoryFd,
    {
        match self.read_key_activability(member_dir, member, kid, now, selection) {
            Ok(activability) => activability,
            Err(error) => KeyActivability::Unreadable(error),
        }
    }

    /// Read the key's documents to the depth `selection` asks for and say what
    /// the key is at `now`.
    fn read_key_activability<D>(
        &self,
        member_dir: &D,
        member: &MemberHandle,
        kid: &Kid,
        now: time::OffsetDateTime,
        selection: KeySelection,
    ) -> Result<KeyActivability>
    where
        D: DirectoryFd,
    {
        let stored =
            self.inspect_stored_key_pair(member_dir, member, kid, selection.private_half_check())?;
        let public_key = match stored {
            StoredKeyPair::NoKeyDirectory => return Ok(KeyActivability::Missing),
            StoredKeyPair::HalfMissing => return Ok(KeyActivability::HalfMissing),
            StoredKeyPair::Present(public_key) => *public_key,
        };
        let expires_at = parse_expires_at(&public_key)?;
        let created_at = parse_created_at(&public_key)?;
        if now >= expires_at {
            return Ok(KeyActivability::Expired(created_at));
        }
        Ok(KeyActivability::Activatable(created_at))
    }

    /// Write the active marker without checking that the key is there.
    ///
    /// Test fixtures build a keystore from parts and set the marker before the
    /// key documents land. Every other caller goes through
    /// `activate_existing_key`, which refuses a marker pointing at nothing.
    #[cfg(any(test, feature = "cli-test-support"))]
    pub(crate) fn set_active_kid_unchecked(&self, member: &MemberHandle, kid: &Kid) -> Result<()> {
        self.write_active_kid_unchecked(member, kid, |_| Ok(()))
    }

    /// Test-only seam around the active-kid write. Compiled out of production.
    #[cfg(test)]
    pub(super) fn set_active_kid_with_staging_hook<H>(
        &self,
        member: &MemberHandle,
        kid: &Kid,
        staging_hook: H,
    ) -> Result<()>
    where
        H: FnOnce(),
    {
        self.write_active_kid_unchecked(member, kid, |member_dir| {
            stage_active_update_for_test(member_dir, staging_hook)
        })
    }

    /// The one locked sequence both unchecked active-kid writes run, with
    /// `stage` marking the window before the marker is published.
    #[cfg(any(test, feature = "cli-test-support"))]
    fn write_active_kid_unchecked<S>(
        &self,
        member: &MemberHandle,
        kid: &Kid,
        stage: S,
    ) -> Result<()>
    where
        S: FnOnce(&ExclusiveLockedDir<'_>) -> Result<()>,
    {
        let member_dir = self.ensure_member(member)?;
        with_exclusive_locked_directory(&member_dir, |locked_member_dir| {
            ensure_member_namespace_safe(locked_member_dir)?;
            let result = stage(locked_member_dir)
                .and_then(|()| save_active_kid_locked(locked_member_dir, kid));
            finish_member_mutation(
                locked_member_dir,
                &locked_member_dir.path().join(ACTIVE_FILE),
                CompletedChange::Written,
                result,
            )
        })
    }

    pub(super) fn load_active_kid_checked<D>(&self, member_dir: &D) -> Result<Option<Kid>>
    where
        D: DirectoryFd,
    {
        ensure_member_namespace_safe(member_dir)?;
        self.load_active_kid_in_verified_namespace(member_dir)
    }

    /// Read the active marker inside a member namespace already inspected by the caller.
    ///
    /// Inspecting the namespace reads the whole member directory, so a caller
    /// that has already done it enters here rather than paying
    /// for a second walk of the same entries.
    pub(super) fn load_active_kid_in_verified_namespace<D>(
        &self,
        member_dir: &D,
    ) -> Result<Option<Kid>>
    where
        D: DirectoryFd,
    {
        // The exposure belongs to the directory, not to the marker inside it,
        // so a member with no active key still has it reported.
        report_violations(collect_open_permission_violations(
            &self.member_permission_chain(member_dir),
        ));
        if !regular_file_exists_at(member_dir, ACTIVE_FILE)? {
            return Ok(None);
        }
        let content = relative::load_text_with_limit_at(
            member_dir,
            ACTIVE_FILE,
            MAX_ACTIVE_KID_FILE_SIZE,
            "active key file",
        )?;
        let value = content.trim();
        if value.is_empty() {
            return Ok(None);
        }
        // The marker is only ever written canonical, and the key directory it
        // names is only ever listed canonical, so accepting display form here
        // would name a key that enumeration cannot see.
        Kid::from_canonical(value).map(Some)
    }

    /// The newest key of `member` that both halves are stored for, expired or
    /// not.
    ///
    /// This answers a read that was never told which key to use, so a key whose
    /// public half cannot be read stops it: quietly resolving to the next key
    /// would hand the caller a key it did not ask about. A key with only one
    /// half stored is passed over, because it can be neither read as a pair nor
    /// signed with, and one such key would otherwise hide every other key the
    /// member holds.
    ///
    /// The private half is settled by its own presence and no further. Whether
    /// the document in it opens is the business of the read that opens it,
    /// which fails naming the key it was handed; deciding it here would let one
    /// key nobody is going to open take down the resolution for all of them.
    fn select_most_recent_kid<D>(&self, member_dir: &D, member: &MemberHandle) -> Result<Kid>
    where
        D: DirectoryFd,
    {
        let SelectableKeys {
            candidates,
            half_missing,
            unreadable,
            ..
        } = self.collect_selectable_keys(member_dir, member, KeySelection::Resolution)?;
        if let Some(error) = unreadable.into_iter().next() {
            return Err(error);
        }
        select_preferred_kid(candidates).ok_or_else(|| no_usable_key_found(member, &half_missing))
    }
}

/// Whether one stored key may be made active, and what rules it out.
///
/// A key missing either half cannot be signed with, and an expired one is
/// refused by every command that would use it, so neither is a key a member can
/// be handed. A key whose documents could not be read carries the failure that
/// stopped it. Every key that was read carries the creation timestamp it
/// states, which is what orders it against the member's other keys.
enum KeyActivability {
    Activatable(Option<time::OffsetDateTime>),
    Expired(Option<time::OffsetDateTime>),
    /// The keystore holds nothing under this key id.
    Missing,
    /// The key id is there with one of its two documents gone.
    HalfMissing,
    Unreadable(Error),
}

/// What a walk over a member's keys is choosing a key for.
///
/// Activation hands the member the key it will sign and decrypt with, so it
/// passes over a key that has run out of validity and settles that the private
/// half reads back as this member's key before offering it: a marker on
/// anything less takes the member's signing and encryption down while `key
/// list` still shows the key.
///
/// Resolving a key nobody named only picks which stored key a command reads.
/// An expired key is still one of those, and so is a key whose private half
/// will not open: the read that opens it fails there, naming the key it was
/// handed, which is closer to what happened than hiding every other key of the
/// member behind it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KeySelection {
    Activation,
    Resolution,
}

impl KeySelection {
    fn accepts_expired(self) -> bool {
        self == Self::Resolution
    }

    fn private_half_check(self) -> PrivateHalfCheck {
        match self {
            Self::Activation => PrivateHalfCheck::Readable,
            Self::Resolution => PrivateHalfCheck::Stored,
        }
    }
}

/// The keys of one member the selection may choose from, and what ruled the
/// rest of them out.
#[derive(Default)]
struct SelectableKeys {
    /// Every key directory the member holds, however it was judged.
    stored: usize,
    candidates: Vec<(Kid, Option<time::OffsetDateTime>)>,
    /// Keys stored with only one of the two documents a key has to hold.
    half_missing: Vec<Kid>,
    unreadable: Vec<Error>,
}

pub(super) fn no_keys_found(member: &MemberHandle) -> Error {
    Error::build_not_found_error(format!("No keys found for member: {}", member))
}

/// Refuse to activate a key that has already expired.
///
/// Naming the key rather than reporting it as absent keeps the operator from
/// looking for a key that `key list` still shows: the key is there, and what it
/// has run out of is validity.
fn expired_key_not_activatable(member: &MemberHandle, kid: &Kid) -> Error {
    Error::build_invalid_operation_error(format!(
        "Key '{}' of member '{}' has expired, so it cannot be made active. Generate a new key \
         with 'kapsaro key new', or name a key that is still valid.",
        kid, member
    ))
}

/// Refuse to activate a key stored with only one of its two documents.
///
/// The key directory is there and `key list` still shows it, so reporting the
/// key as absent would send the operator looking for something they can see.
/// The wording matches how the automatic selection names the same key, so the
/// state reads the same whether or not the operator named a key id.
fn half_missing_key_not_activatable(member: &MemberHandle, kid: &Kid) -> Error {
    Error::build_invalid_operation_error(format!(
        "Key '{}' of member '{}' is missing one of the two key documents, so it cannot be made \
         active. Repair the key directory, or name a key that is stored complete.",
        kid, member
    ))
}

/// Report that the member has keys but none of them can be activated.
///
/// Naming the reasons keeps the operator from reading it as "no keys at all",
/// which `key list` would immediately contradict. Each key that was ruled out
/// for something repairable is named, so the operator is told what to repair
/// rather than only that nothing was chosen.
fn no_activatable_key_found(
    member: &MemberHandle,
    half_missing: &[Kid],
    unreadable: &[Error],
) -> Error {
    let mut message = format!(
        "No key that can be activated found for member: {}. Every key is either expired, missing \
         one of its halves, or unreadable.",
        member
    );
    message.push_str(&describe_ruled_out_keys(half_missing, unreadable));
    Error::build_not_found_error(message)
}

/// Report a member whose stored keys are all missing one of their halves.
///
/// The key directories are there, so calling the member keyless would send the
/// operator looking for something `key list` still shows. A stored key holds
/// both documents or it is not a key anything can use, so the incomplete ones
/// are named as the local state to repair.
fn no_usable_key_found(member: &MemberHandle, half_missing: &[Kid]) -> Error {
    if half_missing.is_empty() {
        return no_keys_found(member);
    }
    Error::build_not_found_error(format!(
        "No usable key found for member: {}. Every key this member holds is incomplete, so the \
         keystore has to be repaired before a key can be resolved without naming one.{}",
        member,
        describe_ruled_out_keys(half_missing, &[])
    ))
}

/// Name the keys a selection had to pass over, one line each.
fn describe_ruled_out_keys(half_missing: &[Kid], unreadable: &[Error]) -> String {
    let mut detail = String::new();
    for kid in half_missing {
        detail.push_str(&format!(
            "\n  Key '{}' is missing one of the two key documents.",
            kid
        ));
    }
    for error in unreadable {
        detail.push_str(&format!(
            "\n  A key of this member could not be read: {}",
            error.format_user_message()
        ));
    }
    detail
}

fn save_active_kid_locked(member_dir: &ExclusiveLockedDir<'_>, kid: &Kid) -> Result<()> {
    relative::save_text_restricted_at(member_dir, ACTIVE_FILE, &format!("{}\n", kid.as_str()))
}

pub(super) fn clear_active_kid_locked(
    member_dir: &ExclusiveLockedDir<'_>,
    member: &MemberHandle,
) -> Result<()> {
    if !regular_file_exists_at(member_dir, ACTIVE_FILE)? {
        return Ok(());
    }
    relative::remove_file_if_exists_at(member_dir, ACTIVE_FILE)
        .map_err(|error| describe_active_removal_failure(error, member_dir, member))
}

/// Tell a marker that is still standing from one that is gone but not persisted.
///
/// The removal unlinks the entry and then persists the directory entry, and
/// reports either failure the same way. Looking at the name afterwards settles
/// which of the two it was: a marker still there means the unlink never
/// happened, so nothing changed and the failure is passed on as it came.
/// Whatever cannot be settled keeps that reading, because claiming a removal
/// that did not happen is what sends the operator looking for the wrong repair.
fn describe_active_removal_failure(
    error: Error,
    member_dir: &ExclusiveLockedDir<'_>,
    member: &MemberHandle,
) -> Error {
    match regular_file_exists_at(member_dir, ACTIVE_FILE) {
        Ok(false) => build_unsynced_active_removal_error(error, member_dir, member),
        Ok(true) => build_standing_active_marker_error(error, member_dir),
        Err(_) => error,
    }
}

/// Report an active marker the removal could not unlink.
///
/// Nothing about the member changed, so the marker still names the key it named
/// before. Saying so keeps this apart from the marker that is already gone and
/// only unpersisted, which asks the operator for an entirely different repair.
fn build_standing_active_marker_error(error: Error, member_dir: &ExclusiveLockedDir<'_>) -> Error {
    Error::build_io_error(format!(
        "The active key marker {} could not be removed and still names the key it named before: {}",
        format_finding_path(&member_dir.path().join(ACTIVE_FILE)),
        error.format_user_message()
    ))
}

/// Report a marker that is already gone but whose removal was not persisted.
///
/// The unlink happens before the directory entry is synced, so a failure here
/// leaves the member with no active key. Reporting only the sync failure reads
/// as "nothing changed", and the operator would not know that the next command
/// resolving a key without naming one may now pick a different key.
fn build_unsynced_active_removal_error(
    error: Error,
    member_dir: &ExclusiveLockedDir<'_>,
    member: &MemberHandle,
) -> Error {
    Error::build_io_error(format_post_change_failure(
        "The active key marker",
        &member_dir.path().join(ACTIVE_FILE),
        CompletedChange::Removed,
        format!(
            "its directory entry was not persisted, so the member has no active key until \
             'kapsaro key activate <kid> --member-handle {}' names one",
            member
        )
        .as_str(),
        error.format_user_message(),
    ))
}

/// Test-only seam: writes and removes a staging file around the hook so a test
/// can observe the member directory mid-mutation. Compiled out of production.
#[cfg(test)]
fn stage_active_update_for_test<H>(
    member_dir: &ExclusiveLockedDir<'_>,
    staging_hook: H,
) -> Result<()>
where
    H: FnOnce(),
{
    const STAGING_FILE: &str = ".active.tmp.test";
    relative::save_text_restricted_at(member_dir, STAGING_FILE, "staging")?;
    staging_hook();
    relative::remove_file_if_exists_at(member_dir, STAGING_FILE)
}

/// The creation timestamp a public key states, if it states one.
///
/// The field is optional in the signed statement, and a key that omits it can
/// no longer be re-signed by whoever reads it, so an absent timestamp orders
/// the key last rather than failing the read. A timestamp that is present but
/// unparsable is still an error: the document says something it does not mean.
fn parse_created_at(public_key: &PublicKey) -> Result<Option<time::OffsetDateTime>> {
    let Some(value) = public_key.protected.created_at.as_deref() else {
        return Ok(None);
    };
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map(Some)
        .map_err(|error| {
            Error::build_parse_error_with_source(
                format!(
                    "Invalid created_at format for key {}: {}",
                    public_key.protected.kid, error
                ),
                error,
            )
        })
}

fn parse_expires_at(public_key: &PublicKey) -> Result<time::OffsetDateTime> {
    time::OffsetDateTime::parse(
        &public_key.protected.expires_at,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|error| {
        Error::build_parse_error_with_source(
            format!(
                "Invalid expires_at format for key {}: {}",
                public_key.protected.kid, error
            ),
            error,
        )
    })
}

/// The newest of several keys, with the canonically first `kid` breaking ties.
///
/// A key stating no creation time sorts behind every key that states one, so it
/// is chosen only when nothing else is on offer.
fn select_preferred_kid(mut candidates: Vec<(Kid, Option<time::OffsetDateTime>)>) -> Option<Kid> {
    candidates.sort_by(|(kid_a, created_at_a), (kid_b, created_at_b)| {
        created_at_b
            .cmp(created_at_a)
            .then_with(|| kid_a.cmp(kid_b))
    });
    candidates.into_iter().next().map(|(kid, _)| kid)
}
