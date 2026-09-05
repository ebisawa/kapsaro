// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Key document persistence for one keystore member.
//! Loads, publishes and removes the private and public halves of a key.

use super::active::{clear_active_kid_locked, no_keys_found};
use super::inspection::list_kids_in_verified_namespace;
use super::{
    ensure_key_directory_safe, ensure_member_namespace_safe, finish_member_mutation,
    key_half_missing, key_not_found, open_required_key_in_verified_namespace, KeystoreAccess,
    MemberPublicKeySnapshot, PublicKeySnapshotEntry, PRIVATE_KEY_FILE, PUBLIC_KEY_FILE,
};
use crate::format::schema::document::{parse_private_key_str, parse_public_key_str};
use crate::io::document_store;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::private_key::PrivateKey;
use crate::model::public_key::PublicKey;
use crate::support::fs::lock::{with_exclusive_locked_directory, ExclusiveLockedDir};
use crate::support::fs::permission::{
    collect_open_permission_violations, inspect_scoped_open_permission, report_violations,
    PermissionViolation, PermissionViolationKind,
};
use crate::support::fs::read::{decode_loaded_text, load_capped_bytes};
use crate::support::fs::relative::{
    self, list_child_entries_at, open_optional_child_dir, regular_file_exists_at, ChildType,
    DirectoryFd, OpenDir,
};
use crate::support::limits::MAX_JSON_DOCUMENT_READ_SIZE;
use crate::support::path::{format_finding_path, format_path_relative_to_cwd};
use crate::support::post_write::{format_post_change_failure, CompletedChange};
use crate::{Error, Result};
use std::fs::File;
use std::path::Path;
use zeroize::Zeroizing;

#[cfg(test)]
#[path = "../../../../tests/unit/internal/io_keystore_access_key_pair_test.rs"]
mod io_keystore_access_key_pair_test;

/// What the keystore holds under one key id, once its documents have been read.
pub(super) enum KeyPairRecord {
    /// No directory stands under the key id at all.
    NoKeyDirectory,
    /// The directory is there with one of the two documents gone.
    HalfMissing,
    /// Both documents are there, parse, and state the member and key the
    /// directory names. The public half travels on because every caller asking
    /// this question reads the key's validity window out of it next. It travels
    /// boxed so that the answer stays small for the outcomes that carry nothing.
    Present(Box<PublicKey>),
}

/// How far an inspection goes into the private half of a key.
///
/// Activation hands the member the key it will sign and decrypt with, so the
/// document has to parse and to state the member and key it is stored under
/// before the marker can be moved onto it. A walk that was only asked which key
/// to read settles for the document standing there: the private half is opened
/// by the read that needs it, which fails naming the key it was handed, and
/// ruling the key out here instead would hide every other key the member holds
/// behind one key the caller may never open.
#[derive(Clone, Copy)]
pub(super) enum PrivateHalfCheck {
    Stored,
    Readable,
}

impl KeystoreAccess {
    /// Remove one key after `validate` approves it, reporting whether it was active.
    ///
    /// `validate` runs while this member directory is locked, so it must not
    /// touch the keystore again: a nested lock on the same directory deadlocks.
    pub(crate) fn remove_key_with_validation<F>(
        &self,
        member: &MemberHandle,
        kid: &Kid,
        validate: F,
    ) -> Result<bool>
    where
        F: FnOnce(bool) -> Result<()>,
    {
        let member_dir = self.open_member(member)?.ok_or_else(|| {
            Error::build_not_found_error(format!("Member '{}' not found", member))
        })?;
        with_exclusive_locked_directory(&member_dir, |locked_member_dir| {
            ensure_member_namespace_safe(locked_member_dir)?;
            let result = self.remove_key_locked(locked_member_dir, member, kid, validate);
            finish_member_mutation(
                locked_member_dir,
                &locked_member_dir.path().join(kid.as_str()),
                CompletedChange::Removed,
                result,
            )
        })
    }

    /// Settle whether removing one key would be refused, removing nothing.
    ///
    /// Every refusal `remove_key_with_validation` raises before it deletes
    /// anything is raised here too before this returns. A caller whose earlier
    /// steps cannot be undone asks first,
    /// so a removal that was never going to happen stops before them.
    ///
    /// This is what the keystore held when it was asked rather than a promise
    /// about later. The removal decides again under its own exclusive lock.
    pub(crate) fn ensure_key_removable<F>(
        &self,
        member: &MemberHandle,
        kid: &Kid,
        validate: F,
    ) -> Result<()>
    where
        F: FnOnce(bool) -> Result<()>,
    {
        let member_dir = self.open_member(member)?.ok_or_else(|| {
            Error::build_not_found_error(format!("Member '{}' not found", member))
        })?;
        ensure_member_namespace_safe(&member_dir)?;
        let active = self.load_active_kid_in_verified_namespace(&member_dir)?;
        let was_active = active.as_ref() == Some(kid);
        validate(was_active)?;
        build_key_removal_plan(&member_dir, member, kid).map(|_| ())
    }

    /// Load the private half of one key, refusing a key stored without its
    /// public half.
    ///
    /// The two halves are read as a pair. A private half whose public half is
    /// gone names a key no verification can complete, and handing it back as a
    /// key that loaded would leave that condition to surface later, somewhere
    /// further from what caused it.
    pub(crate) fn load_private_key(&self, member: &MemberHandle, kid: &Kid) -> Result<PrivateKey> {
        self.load_key_pair(member, kid)
            .map(|(private_key, _)| private_key)
    }

    /// Load both halves of one named published key through one opened directory.
    pub(crate) fn load_key_pair(
        &self,
        member: &MemberHandle,
        kid: &Kid,
    ) -> Result<(PrivateKey, PublicKey)> {
        let member_dir = self.open_member(member)?.ok_or_else(|| {
            Error::build_not_found_error(format!("Member '{}' not found", member))
        })?;
        self.load_key_pair_checked(&member_dir, member, kid)
    }

    /// Resolve which key `query` names and read both halves through one opened
    /// member directory.
    ///
    /// Both operations stay bound to one opened member directory. A concurrent
    /// removal may produce a retryable read failure, while a published key
    /// directory is never replaced with different content.
    pub(crate) fn resolve_key_pair(
        &self,
        member: &MemberHandle,
        query: Option<&str>,
    ) -> Result<(Kid, PrivateKey, PublicKey)> {
        let member_dir = self
            .open_member(member)?
            .ok_or_else(|| no_keys_found(member))?;
        let kid = self.resolve_kid_in_verified_namespace(&member_dir, member, query)?;
        let (private_key, public_key) =
            self.load_key_pair_in_verified_namespace(&member_dir, member, &kid)?;
        Ok((kid, private_key, public_key))
    }

    /// Read both halves after validating the opened member namespace.
    fn load_key_pair_checked<D>(
        &self,
        member_dir: &D,
        member: &MemberHandle,
        kid: &Kid,
    ) -> Result<(PrivateKey, PublicKey)>
    where
        D: DirectoryFd,
    {
        ensure_member_namespace_safe(member_dir)?;
        self.load_key_pair_in_verified_namespace(member_dir, member, kid)
    }

    /// Read both halves inside a member namespace already inspected by the caller.
    ///
    /// The key directory is opened once and both documents are read through
    /// that file descriptor, so the private and public halves always describe
    /// the same key directory even if the path is replaced while they are read.
    fn load_key_pair_in_verified_namespace<D>(
        &self,
        member_dir: &D,
        member: &MemberHandle,
        kid: &Kid,
    ) -> Result<(PrivateKey, PublicKey)>
    where
        D: DirectoryFd,
    {
        let key_dir = open_required_key_in_verified_namespace(member_dir, member, kid)?;
        run_key_directory_open_hook();
        let permission_chain = self.key_permission_chain(member_dir, &key_dir);
        let private_key = load_private_key_at(&key_dir, &permission_chain, member, kid)?;
        let public_key = load_optional_public_key_at(&key_dir, &permission_chain, member, kid)?
            .ok_or_else(|| key_half_missing(member, kid))?;
        Ok((private_key, public_key))
    }

    pub(crate) fn load_public_key(&self, member: &MemberHandle, kid: &Kid) -> Result<PublicKey> {
        self.load_optional_public_key(member, kid)?
            .ok_or_else(|| key_not_found(member, kid))
    }

    pub(crate) fn load_optional_public_key(
        &self,
        member: &MemberHandle,
        kid: &Kid,
    ) -> Result<Option<PublicKey>> {
        let Some(member_dir) = self.open_member(member)? else {
            return Ok(None);
        };
        self.load_optional_public_key_checked(&member_dir, member, kid)
    }

    /// Load a public key inside a member namespace already inspected by the
    /// caller. Readers that walk every key inspect the namespace once instead
    /// of once per key.
    pub(super) fn load_public_key_in_verified_namespace<D>(
        &self,
        member_dir: &D,
        member: &MemberHandle,
        kid: &Kid,
    ) -> Result<PublicKey>
    where
        D: DirectoryFd,
    {
        self.load_optional_public_key_in_verified_namespace(member_dir, member, kid)?
            .ok_or_else(|| key_not_found(member, kid))
    }

    fn load_optional_public_key_checked<D>(
        &self,
        member_dir: &D,
        member: &MemberHandle,
        kid: &Kid,
    ) -> Result<Option<PublicKey>>
    where
        D: DirectoryFd,
    {
        ensure_member_namespace_safe(member_dir)?;
        self.load_optional_public_key_in_verified_namespace(member_dir, member, kid)
    }

    pub(super) fn load_optional_public_key_in_verified_namespace<D>(
        &self,
        member_dir: &D,
        member: &MemberHandle,
        kid: &Kid,
    ) -> Result<Option<PublicKey>>
    where
        D: DirectoryFd,
    {
        let Some(key_dir) = open_optional_child_dir(member_dir, kid.as_str())? else {
            return Ok(None);
        };
        ensure_key_directory_safe(&key_dir)?;
        let permission_chain = self.key_permission_chain(member_dir, &key_dir);
        load_optional_public_key_at(&key_dir, &permission_chain, member, kid)
    }

    /// Every published public key `member` holds together with its active marker.
    ///
    /// A key directory holding no public half contributes an incomplete entry
    /// rather than failing the read: one absence would otherwise hide every
    /// other key of the member, and omitting it would hide the key an operator
    /// needs to repair.
    ///
    /// Only canonical published names are read. A concurrent removal can make
    /// the operation return a retryable failure instead of mixing an unfinished
    /// key-pair publication into the result.
    pub(crate) fn load_public_key_entries_with_active(
        &self,
        member: &MemberHandle,
    ) -> Result<MemberPublicKeySnapshot> {
        let Some(member_dir) = self.open_member(member)? else {
            return Ok((None, Vec::new()));
        };
        let kids = list_kids_in_verified_namespace(&member_dir)?;
        let active = self.load_active_kid_in_verified_namespace(&member_dir)?;
        let mut entries = Vec::new();
        for kid in kids {
            let public_key =
                self.load_optional_public_key_in_verified_namespace(&member_dir, member, &kid)?;
            entries.push(match public_key {
                Some(public_key) => PublicKeySnapshotEntry::Complete {
                    kid,
                    public_key: Box::new(public_key),
                },
                None => PublicKeySnapshotEntry::MissingPublicDocument { kid },
            });
        }
        Ok((active, entries))
    }

    /// The active key of `member`, when both halves of it are present.
    ///
    /// An active marker naming a key whose private half is gone reads as
    /// absence rather than being repaired here. A read that takes an exclusive
    /// lock blocks every concurrent reader and fails outright where the
    /// keystore is mounted read-only, and a caller asking what the active key
    /// is has not asked for the keystore to be changed. The diagnostic command
    /// reports the dangling marker and names `key activate` as the repair.
    pub(crate) fn load_active_public_key_with_private(
        &self,
        member: &MemberHandle,
    ) -> Result<Option<(Kid, PublicKey)>> {
        let Some(member_dir) = self.open_member(member)? else {
            return Ok(None);
        };
        let Some(kid) = self.load_active_kid_checked(&member_dir)? else {
            return Ok(None);
        };
        if !self.private_key_exists_in_verified_namespace(&member_dir, member, &kid)? {
            return Ok(None);
        }
        self.load_public_key_in_verified_namespace(&member_dir, member, &kid)
            .map(|public_key| Some((kid, public_key)))
    }

    pub(crate) fn save_key_pair_atomic(
        &self,
        member: &MemberHandle,
        kid: &Kid,
        private_key: &PrivateKey,
        public_key: &PublicKey,
    ) -> Result<()> {
        let member_dir = self.ensure_member(member)?;
        ensure_member_namespace_safe(&member_dir)?;
        report_violations(collect_open_permission_violations(
            &self.member_permission_chain(&member_dir),
        ));
        let result = publish_key_pair_atomic(&member_dir, member, kid, private_key, public_key);
        finish_member_mutation(
            &member_dir,
            &member_dir.path().join(kid.as_str()),
            CompletedChange::Written,
            result,
        )
    }

    /// Whether the private half of one key is stored, inside a member namespace
    /// already inspected by the caller.
    ///
    /// This asks about the entry standing there rather than about the document
    /// in it. Its caller reports what the member has active, and a marker naming
    /// a key whose private half is gone reads there as no active key at all;
    /// opening the document would turn that into a failure of a read that never
    /// asked for the key itself.
    ///
    /// The caller inspects the member namespace once, so a reader that walks
    /// every key does not re-enumerate the member directory per key.
    /// `load_active_public_key_with_private` reaches that inspection through the
    /// active marker read.
    pub(super) fn private_key_exists_in_verified_namespace<D>(
        &self,
        member_dir: &D,
        member: &MemberHandle,
        kid: &Kid,
    ) -> Result<bool>
    where
        D: DirectoryFd,
    {
        let Some(key_dir) = open_optional_child_dir(member_dir, kid.as_str())? else {
            return Ok(false);
        };
        ensure_key_directory_safe(&key_dir)?;
        let permission_chain = self.key_permission_chain(member_dir, &key_dir);
        inspect_stored_private_half(
            &key_dir,
            &permission_chain,
            member,
            kid,
            PrivateHalfCheck::Stored,
        )
    }

    /// Read both halves of one key from one key-directory snapshot and say what
    /// the keystore holds under that key id.
    ///
    /// `private_half` is what the caller is choosing a key for: activation
    /// settles that the private half reads back as this member's key, while a
    /// walk picking which stored key to read settles for the document standing
    /// there.
    ///
    /// Both documents are read through one opened key directory, so they
    /// describe the same directory even if the path is replaced while they are
    /// read. A key stored without either of its two documents is reported as
    /// incomplete rather than as unreadable, because the two ask the operator
    /// for different repairs.
    pub(super) fn inspect_stored_key_pair<D>(
        &self,
        member_dir: &D,
        member: &MemberHandle,
        kid: &Kid,
        private_half: PrivateHalfCheck,
    ) -> Result<KeyPairRecord>
    where
        D: DirectoryFd,
    {
        let Some(key_dir) = open_optional_child_dir(member_dir, kid.as_str())? else {
            return Ok(KeyPairRecord::NoKeyDirectory);
        };
        ensure_key_directory_safe(&key_dir)?;
        let permission_chain = self.key_permission_chain(member_dir, &key_dir);
        if !inspect_stored_private_half(&key_dir, &permission_chain, member, kid, private_half)? {
            return Ok(KeyPairRecord::HalfMissing);
        }
        match load_optional_public_key_at(&key_dir, &permission_chain, member, kid)? {
            Some(public_key) => Ok(KeyPairRecord::Present(Box::new(public_key))),
            None => Ok(KeyPairRecord::HalfMissing),
        }
    }

    fn remove_key_locked<F>(
        &self,
        member_dir: &ExclusiveLockedDir<'_>,
        member: &MemberHandle,
        kid: &Kid,
        validate: F,
    ) -> Result<bool>
    where
        F: FnOnce(bool) -> Result<()>,
    {
        // The caller inspected the member namespace when it took the lock.
        let active = self.load_active_kid_in_verified_namespace(member_dir)?;
        let was_active = active.as_ref() == Some(kid);
        validate(was_active)?;
        let prepared = build_key_removal_plan(member_dir, member, kid)?;
        // The marker goes first. A deletion that stops partway would otherwise
        // leave `active` naming a key whose private half is gone, which every
        // later load reports as a missing key; clearing it first leaves the
        // lighter state of no active key, which `key activate` settles.
        if was_active {
            clear_active_kid_locked(member_dir, member)?;
        }
        execute_key_directory_removal(member_dir, kid, prepared).map_err(|error| {
            build_interrupted_removal_error(member_dir, member, kid, was_active, error)
        })?;
        Ok(was_active)
    }
}

/// Settle the private half of one key to the depth `check` asks for, reporting
/// whether the keystore holds it at all.
///
/// An absent private half reads the same either way. What the check decides is
/// whether a document that is there also has to read back as this member's key
/// before it counts as stored.
fn inspect_stored_private_half(
    key_dir: &OpenDir,
    permission_chain: &[&dyn DirectoryFd],
    member: &MemberHandle,
    kid: &Kid,
    check: PrivateHalfCheck,
) -> Result<bool> {
    if !regular_file_exists_at(key_dir, PRIVATE_KEY_FILE)? {
        report_violations(collect_open_permission_violations(permission_chain));
        return Ok(false);
    }
    match check {
        PrivateHalfCheck::Stored => report_stored_private_half_exposure(key_dir, permission_chain),
        // The document is read for what it states about itself and dropped
        // again. Nothing here unwraps the key, so holding it past the check
        // would keep key material alive for no reader.
        PrivateHalfCheck::Readable => {
            load_private_key_at(key_dir, permission_chain, member, kid).map(|_| ())
        }
    }?;
    Ok(true)
}

/// Name what the ancestry and the private key document expose, for a caller
/// that settles the private half on the entry standing there and never opens
/// the document. The read that does open it raises the same findings itself.
fn report_stored_private_half_exposure(
    key_dir: &OpenDir,
    permission_chain: &[&dyn DirectoryFd],
) -> Result<()> {
    let mut violations = collect_open_permission_violations(permission_chain);
    let private_path = key_dir.path().join(PRIVATE_KEY_FILE);
    let private_file = relative::open_regular_file_at(key_dir, PRIVATE_KEY_FILE)?;
    violations.extend(inspect_scoped_open_permission(
        key_dir,
        &private_file,
        &private_path,
    ));
    report_violations(violations);
    Ok(())
}

/// Read the private half from an already opened key directory.
///
/// The file is opened once, and the exposure check, the capped read and the
/// parse all run on that one descriptor. Checking the name and opening it again
/// to read would leave a window in which the entry can be replaced, and a key
/// directory another account can write is precisely the situation the exposure
/// check exists for.
fn load_private_key_at(
    key_dir: &OpenDir,
    permission_chain: &[&dyn DirectoryFd],
    member: &MemberHandle,
    kid: &Kid,
) -> Result<PrivateKey> {
    let path = key_dir.path().join(PRIVATE_KEY_FILE);
    // Reported before the refusal below, so an operator whose private key is
    // exposed is told about every entry that has to be repaired rather than
    // only the one that stopped the read.
    report_violations(collect_open_permission_violations(permission_chain));
    let mut private_file = relative::open_regular_file_at(key_dir, PRIVATE_KEY_FILE)?;
    ensure_open_private_key_is_owner_only(key_dir, &private_file, &path)?;
    run_private_key_checked_hook();
    let private_key = load_open_private_key(&mut private_file, &path)?;
    ensure_document_states_stored_identity(private_key_identity(&private_key), member, kid, &path)?;
    Ok(private_key)
}

/// Refuse to hand back a private key another account can already reach.
///
/// Every other entry of local state is named as a warning and the command goes
/// on, because the mode of a file on a shared host is the operator's decision.
/// The private half is the one entry where that decision cannot be deferred:
/// once it is read out, whoever else could read it holds the key too, and a
/// warning printed beside the result arrives after the fact. Only a mode that
/// is wrong and an owner that is somebody else stop the read; a mode that could
/// not be established says nothing about the exposure and keeps the warning
/// route the read itself takes.
fn ensure_open_private_key_is_owner_only(
    key_dir: &OpenDir,
    private_file: &File,
    path: &Path,
) -> Result<()> {
    let Some(violation) = inspect_scoped_open_permission(key_dir, private_file, path) else {
        return Ok(());
    };
    match violation.kind() {
        PermissionViolationKind::InsecureMode | PermissionViolationKind::ForeignOwner => {
            Err(build_exposed_private_key_error(&violation))
        }
        // Spelled out one kind at a time rather than caught by a wildcard. A
        // kind added later has to be judged against the private half here, and
        // a compile error is what asks for that judgment; a wildcard would put
        // the new kind on the warning route without anyone deciding it belongs
        // there. Of the kinds listed, only `Unreadable` describes a file that
        // is already open, and the rest report what a scan met on the way.
        PermissionViolationKind::Unreadable
        | PermissionViolationKind::UndecodableName
        | PermissionViolationKind::UnexpectedEntryType
        | PermissionViolationKind::ReplacedEntry
        | PermissionViolationKind::InsecureAncestor
        | PermissionViolationKind::UnreadableAncestor
        | PermissionViolationKind::UnresolvableAncestry
        | PermissionViolationKind::IncompleteScan => {
            report_violations(vec![violation]);
            Ok(())
        }
    }
}

/// Read and parse the private key document from the descriptor already checked.
///
/// The source text is wiped once the document is built, the way every other
/// loader of a key document wipes it. The wipe is best effort: the read grows
/// its buffer as it goes, and a copy left in a freed allocation is out of reach.
fn load_open_private_key(private_file: &mut File, path: &Path) -> Result<PrivateKey> {
    let display_path = format_path_relative_to_cwd(path);
    let bytes = load_capped_bytes(
        private_file,
        MAX_JSON_DOCUMENT_READ_SIZE,
        "PrivateKey file",
        &display_path,
    )?;
    let content = Zeroizing::new(decode_loaded_text(bytes, &display_path)?);
    parse_private_key_str(&content, &display_path)
}

/// Report the exposure that stopped the read, with the repair it already names.
///
/// The finding carries the wording and the repair command the diagnostic shows
/// for the same entry, so the operator is told to run one `chmod` rather than
/// two different things depending on which command met the file.
fn build_exposed_private_key_error(violation: &PermissionViolation) -> Error {
    Error::build_local_state_private_key_exposed_error(format!(
        "Refusing to read a private key that is not owner-only: {}",
        violation.message()
    ))
}

/// Read the public half from an already opened key directory.
fn load_optional_public_key_at(
    key_dir: &OpenDir,
    permission_chain: &[&dyn DirectoryFd],
    member: &MemberHandle,
    kid: &Kid,
) -> Result<Option<PublicKey>> {
    let path = key_dir.path().join(PUBLIC_KEY_FILE);
    let loaded = document_store::load_optional_at(
        key_dir,
        &path,
        permission_chain,
        MAX_JSON_DOCUMENT_READ_SIZE,
        "PublicKey file",
        |content| parse_public_key_str(content, &format_path_relative_to_cwd(&path)),
    )?;
    let Some(public_key) = loaded.map(|loaded| loaded.document) else {
        return Ok(None);
    };
    ensure_document_states_stored_identity(public_key_identity(&public_key), member, kid, &path)?;
    Ok(Some(public_key))
}

/// The member and key one stored key document states about itself.
struct StatedKeyIdentity<'a> {
    subject_handle: &'a str,
    kid: &'a str,
}

fn private_key_identity(private_key: &PrivateKey) -> StatedKeyIdentity<'_> {
    StatedKeyIdentity {
        subject_handle: &private_key.protected.subject_handle,
        kid: &private_key.protected.kid,
    }
}

fn public_key_identity(public_key: &PublicKey) -> StatedKeyIdentity<'_> {
    StatedKeyIdentity {
        subject_handle: &public_key.protected.subject_handle,
        kid: &public_key.protected.kid,
    }
}

/// Refuse a key document that does not state the member and key its path names.
///
/// The keystore addresses a key by its directory, so nothing else ties the
/// bytes under `keys/<member>/<kid>/` to that member and that key. Another
/// member's intact, correctly signed key pair copied there would otherwise be
/// handed back as the key of whoever was asked for.
fn ensure_document_states_stored_identity(
    stated: StatedKeyIdentity<'_>,
    member: &MemberHandle,
    kid: &Kid,
    path: &Path,
) -> Result<()> {
    if stated.subject_handle == member.as_str() && stated.kid == kid.as_str() {
        return Ok(());
    }
    Err(Error::build_local_state_path_unsafe_error(format!(
        "key document stating member '{}' key '{}' stored as member '{}' key '{}': {}",
        stated.subject_handle,
        stated.kid,
        member,
        kid,
        format_finding_path(path)
    )))
}

/// Test-only seam: runs once the key directory is opened and before either
/// document is read, so a test can replace the path underneath.
#[cfg(test)]
fn run_key_directory_open_hook() {
    let hook = KEY_DIRECTORY_OPEN_HOOK.with(|hook| hook.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(not(test))]
fn run_key_directory_open_hook() {}

// Test-only seam: fires when a member key directory is opened, so a test can
// prove which lock windows do and do not reach the keystore.
#[cfg(test)]
thread_local! {
    static KEY_DIRECTORY_OPEN_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Arm the key directory open seam for the next key pair load on this thread.
#[cfg(test)]
pub(crate) fn set_key_directory_open_hook<H>(hook: H)
where
    H: FnOnce() + 'static,
{
    KEY_DIRECTORY_OPEN_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

/// Test-only seam: runs once the private key file is open and its exposure has
/// been settled, and before a byte of it is read, so a test can replace the
/// entry in the window the check would otherwise leave open.
#[cfg(test)]
fn run_private_key_checked_hook() {
    let hook = PRIVATE_KEY_CHECKED_HOOK.with(|hook| hook.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(not(test))]
fn run_private_key_checked_hook() {}

// Test-only seam: fires between the exposure check and the read, which is the
// window an entry replaced under a writable key directory would land in.
#[cfg(test)]
thread_local! {
    static PRIVATE_KEY_CHECKED_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Arm the private key check seam for the next private key read on this thread.
#[cfg(test)]
pub(crate) fn set_private_key_checked_hook<H>(hook: H)
where
    H: FnOnce() + 'static,
{
    PRIVATE_KEY_CHECKED_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

/// Test-only seam: runs while the staged key directory exists and has not been
/// renamed into place, so a test can observe or disturb that window.
#[cfg(test)]
fn run_key_pair_staged_hook() {
    let hook = KEY_PAIR_STAGED_HOOK.with(|hook| hook.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(not(test))]
fn run_key_pair_staged_hook() {}

// Test-only seam: fires while the key pair is staged and not yet published,
// which is the window a concurrent reader or a failing publish meets.
#[cfg(test)]
thread_local! {
    static KEY_PAIR_STAGED_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Arm the key pair staging seam for the next key pair write on this thread.
#[cfg(test)]
pub(crate) fn set_key_pair_staged_hook<H>(hook: H)
where
    H: FnOnce() + 'static,
{
    KEY_PAIR_STAGED_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

/// A key directory checked over and ready to be deleted.
struct KeyRemovalPlan {
    key_dir: OpenDir,
    entries: Vec<(String, ChildType)>,
}

/// Open one key directory and confirm every entry in it can be deleted.
///
/// Removability is settled across the whole directory before anything is
/// removed, so meeting an undeletable entry costs nothing: no key document has
/// been touched and no marker has been cleared. Nothing here writes, so a
/// caller asking the question ahead of time performs only published reads.
fn build_key_removal_plan<D>(
    member_dir: &D,
    member: &MemberHandle,
    kid: &Kid,
) -> Result<KeyRemovalPlan>
where
    D: DirectoryFd,
{
    let key_dir = open_optional_child_dir(member_dir, kid.as_str())?
        .ok_or_else(|| key_not_found(member, kid))?;
    ensure_key_directory_safe(&key_dir)?;
    let entries = list_child_entries_at(&key_dir)?;
    ensure_key_entries_removable(&key_dir, &entries)?;
    Ok(KeyRemovalPlan { key_dir, entries })
}

/// Delete the key directory the preparation opened.
/// Report a removal that stopped partway, naming what it already undid.
///
/// The marker is cleared before the documents go, so a failure here leaves the
/// member with no active key. Reporting only that the removal failed reads as
/// "nothing changed", and the operator would not know to run `key activate`.
fn build_interrupted_removal_error<D>(
    member_dir: &D,
    member: &MemberHandle,
    kid: &Kid,
    was_active: bool,
    error: Error,
) -> Error
where
    D: DirectoryFd,
{
    if !was_active {
        return error;
    }
    Error::build_io_error(format_post_change_failure(
        "The active key marker for",
        member_dir.path(),
        CompletedChange::Removed,
        format!(
            "removing key directory '{}' then stopped partway, so the member has no active key \
             until 'kapsaro key activate <kid> --member-handle {}' names one",
            kid, member
        )
        .as_str(),
        error.format_user_message(),
    ))
}

fn execute_key_directory_removal(
    member_dir: &ExclusiveLockedDir<'_>,
    kid: &Kid,
    prepared: KeyRemovalPlan,
) -> Result<()> {
    for (name, child_type) in &prepared.entries {
        remove_child_entry(&prepared.key_dir, name, *child_type)?;
    }
    relative::remove_empty_child_dir_if_exists_at(member_dir, kid.as_str())
}

/// Reject a key directory holding an entry that cannot be deleted, before any
/// deletion happens. Only an empty child directory is removable.
fn ensure_key_entries_removable(key_dir: &OpenDir, entries: &[(String, ChildType)]) -> Result<()> {
    for (name, child_type) in entries {
        if *child_type != ChildType::Directory {
            continue;
        }
        let Some(child) = open_optional_child_dir(key_dir, name)? else {
            continue;
        };
        if !list_child_entries_at(&child)?.is_empty() {
            return Err(Error::build_local_state_path_unsafe_error(format!(
                "refusing to remove a key directory holding a non-empty entry: {}",
                format_path_relative_to_cwd(&key_dir.path().join(name))
            )));
        }
    }
    Ok(())
}

fn remove_child_entry<D>(dir: &D, name: &str, child_type: ChildType) -> Result<()>
where
    D: DirectoryFd,
{
    match child_type {
        ChildType::Directory => relative::remove_empty_child_dir_if_exists_at(dir, name),
        _ => relative::remove_file_if_exists_at(dir, name),
    }
}

fn publish_key_pair_atomic(
    member_dir: &OpenDir,
    member: &MemberHandle,
    kid: &Kid,
    private_key: &PrivateKey,
    public_key: &PublicKey,
) -> Result<()> {
    ensure_key_pair_states_stored_identity(member_dir, member, kid, private_key, public_key)?;
    let temp_name = relative::unique_staging_dir_name();
    let temp_dir = relative::save_child_dir_restricted_at(member_dir, &temp_name)?;
    run_key_pair_staged_hook();
    if let Err(error) = publish_staged_key_pair(
        member_dir,
        &temp_dir,
        &temp_name,
        kid,
        private_key,
        public_key,
    ) {
        let cleanup = cleanup_temp_key_dir(member_dir, &temp_dir, &temp_name);
        return Err(report_with_staging_residue(error, &temp_dir, cleanup));
    }
    sync_published_key_pair(member_dir)
        .map_err(|error| build_unsynced_key_pair_error(error, member_dir, kid))
}

/// Write both documents into the staged directory and rename it into place.
fn publish_staged_key_pair(
    member_dir: &OpenDir,
    temp_dir: &OpenDir,
    temp_name: &str,
    kid: &Kid,
    private_key: &PrivateKey,
    public_key: &PublicKey,
) -> Result<()> {
    save_key_pair_files(temp_dir, private_key, public_key)?;
    relative::rename_child_noreplace_unsynced_at(member_dir, temp_name, kid.as_str())
}

/// Keep the failure that stopped the write, naming the staging it left behind.
///
/// The write is what the operator asked about, so its failure leads. A staging
/// directory that survived is ignored by normal readers and reported by Doctor,
/// so it is named here while the failed command still knows its origin.
fn report_with_staging_residue(error: Error, temp_dir: &OpenDir, cleanup: Result<()>) -> Error {
    let Err(cleanup_error) = cleanup else {
        return error;
    };
    Error::build_io_error(format!(
        "{}. A key staging directory was left behind at {} and should be inspected and removed: {}",
        error.format_user_message(),
        format_finding_path(temp_dir.path()),
        cleanup_error.format_user_message()
    ))
}

/// Report a key pair the rename published but whose entry was not persisted.
///
/// The rename is the point the key pair becomes readable, and it already
/// happened, so the failure is about durability rather than about the write.
/// Saying "key generation failed" would send the operator to generate another
/// key, which the entry standing on disk would then refuse.
fn build_unsynced_key_pair_error(error: Error, member_dir: &OpenDir, kid: &Kid) -> Error {
    Error::build_io_error(format_post_change_failure(
        "Key pair",
        &member_dir.path().join(kid.as_str()),
        CompletedChange::Written,
        "its directory entry was not persisted, so a crash before the next sync could lose it",
        error.format_user_message(),
    ))
}

/// Persist the directory entry the rename created.
///
/// A test can make this fail once to check that a key pair left unsynced is
/// still readable and does not strand its staging directory.
#[cfg(test)]
fn sync_published_key_pair(member_dir: &OpenDir) -> Result<()> {
    if FAIL_NEXT_KEY_PAIR_PARENT_SYNC.with(|flag| flag.replace(false)) {
        return Err(Error::build_io_error("Injected parent sync failure"));
    }
    relative::sync_directory_at(member_dir)
}

#[cfg(not(test))]
fn sync_published_key_pair(member_dir: &OpenDir) -> Result<()> {
    relative::sync_directory_at(member_dir)
}

// Fault-injection seam: arms one parent directory sync to fail, which is how
// the tests reach the path a real fsync error would take after the key pair is
// already staged.
#[cfg(test)]
thread_local! {
    static FAIL_NEXT_KEY_PAIR_PARENT_SYNC: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn fail_next_key_pair_parent_sync() {
    FAIL_NEXT_KEY_PAIR_PARENT_SYNC.with(|flag| flag.set(true));
}

/// Refuse to store a key pair under a member and key it does not state.
///
/// The read path settles the same question every time it hands a key back, so
/// a pair written under the wrong name would be readable nowhere. Refusing at
/// the write keeps the mismatch out of the keystore instead.
fn ensure_key_pair_states_stored_identity(
    member_dir: &OpenDir,
    member: &MemberHandle,
    kid: &Kid,
    private_key: &PrivateKey,
    public_key: &PublicKey,
) -> Result<()> {
    let key_path = member_dir.path().join(kid.as_str());
    ensure_document_states_stored_identity(
        private_key_identity(private_key),
        member,
        kid,
        &key_path.join(PRIVATE_KEY_FILE),
    )?;
    ensure_document_states_stored_identity(
        public_key_identity(public_key),
        member,
        kid,
        &key_path.join(PUBLIC_KEY_FILE),
    )
}

fn save_key_pair_files(
    temp_dir: &OpenDir,
    private_key: &PrivateKey,
    public_key: &PublicKey,
) -> Result<()> {
    document_store::save_json_restricted_at(temp_dir, PRIVATE_KEY_FILE, private_key)?;
    document_store::save_json_restricted_at(temp_dir, PUBLIC_KEY_FILE, public_key)
}

/// Remove a staging directory abandoned by a failed key pair write.
///
/// Every entry is removed, files and directories alike, not just the two key
/// documents: a write that failed part way can leave its own atomic-rename
/// temporaries behind, and those would otherwise keep the staging directory
/// alive forever. Every entry is attempted even after one refuses to go, so a
/// staged private key document is never what survives; the first refusal is
/// what the caller is told, alongside the failure the write itself met.
fn cleanup_temp_key_dir(member_dir: &OpenDir, temp_dir: &OpenDir, temp_name: &str) -> Result<()> {
    let mut failure = None;
    for (name, child_type) in list_child_entries_at(temp_dir)? {
        if let Err(error) = remove_child_entry(temp_dir, &name, child_type) {
            failure = failure.or(Some(error));
        }
    }
    match failure {
        Some(error) => Err(error),
        None => relative::remove_empty_child_dir_if_exists_at(member_dir, temp_name),
    }
}
