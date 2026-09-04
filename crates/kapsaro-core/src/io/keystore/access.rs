// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Anchored local-keystore filesystem access.
//! Binds all member and key operations to one opened root directory identity.

use std::path::{Path, PathBuf};

use crate::error::absent_as_none;
use crate::io::keystore::paths::KEYSTORE_DIR_NAME;
use crate::model::identity::{Kid, MemberHandle};
use crate::model::public_key::PublicKey;
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::relative::{
    ensure_child_dir_restricted_at, is_write_staging_name, list_child_entries_at,
    open_optional_child_dir, ChildType, DirectoryFd, DirectoryScope, OpenDir,
};
use crate::support::path::{format_finding_path, format_path_relative_to_cwd};
use crate::support::post_write::{format_post_change_failure, CompletedChange};
use crate::{Error, ErrorKind, Result};

mod active;
mod inspection;
mod key_pair;

// Fault-injection seams defined in `key_pair`, re-exported so tests outside
// this module can force a directory sync failure, observe when the member key
// directory is opened, disturb the private key read once its exposure has been
// settled, or hold a key pair write open while it is staged.
#[cfg(test)]
pub(crate) use key_pair::{
    fail_next_key_pair_parent_sync, set_key_directory_open_hook, set_key_pair_staged_hook,
    set_private_key_checked_hook,
};

pub(super) const ACTIVE_FILE: &str = "active";
pub(super) const PRIVATE_KEY_FILE: &str = "private.json";
pub(super) const PUBLIC_KEY_FILE: &str = "public.json";

pub(super) type MemberPublicKeySnapshot = (Option<Kid>, Vec<PublicKeySnapshotEntry>);

/// One key directory observed while listing a member's public keys.
pub(crate) enum PublicKeySnapshotEntry {
    Complete {
        kid: Kid,
        public_key: Box<PublicKey>,
    },
    MissingPublicDocument {
        kid: Kid,
    },
}

impl PublicKeySnapshotEntry {
    pub(crate) fn kid(&self) -> &Kid {
        match self {
            Self::Complete { kid, .. } | Self::MissingPublicDocument { kid } => kid,
        }
    }
}

/// Cloneable capability bound to one opened keystore root directory.
#[derive(Debug, Clone)]
pub(crate) struct KeystoreAccess {
    root: AnchoredDir,
    home: Option<AnchoredDir>,
}

impl KeystoreAccess {
    /// Open an existing keystore root, bound to the directory it resolved to.
    pub(crate) fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let opened = AnchoredDir::open(root.into(), DirectoryScope::LocalState, "keystore root")?;
        Ok(Self::from_opened(opened))
    }

    /// Open a keystore root, creating the directory when it is not there yet.
    pub(crate) fn ensure(root: impl Into<PathBuf>) -> Result<Self> {
        let opened = AnchoredDir::ensure(root.into(), DirectoryScope::LocalState, "keystore root")?;
        Ok(Self::from_opened(opened))
    }

    pub(crate) fn open_from_home(home: impl Into<PathBuf>) -> Result<Self> {
        let home = AnchoredDir::open(home, DirectoryScope::LocalState, "local state root")?;
        Self::open_from_anchored_home(&home)
    }

    /// Open the keystore under a local state root path, reporting a root or a
    /// `keys` directory that is not there yet as absence.
    ///
    /// A caller that only enumerates what the keystore holds has nothing to do
    /// when there is none, while every other failure keeps its own error.
    pub(crate) fn open_optional_from_home(home: impl Into<PathBuf>) -> Result<Option<Self>> {
        absent_as_none(Self::open_from_home(home))
    }

    pub(crate) fn open_from_anchored_home(home: &AnchoredDir) -> Result<Self> {
        home.open_child(KEYSTORE_DIR_NAME).map(|root| Self {
            root,
            home: Some(home.clone()),
        })
    }

    /// Open the keystore under one opened local state root, reporting an absent
    /// `keys` directory as absence rather than as a failure.
    pub(crate) fn open_optional_from_anchored_home(home: &AnchoredDir) -> Result<Option<Self>> {
        absent_as_none(Self::open_from_anchored_home(home))
    }

    /// Open the keystore under one local state root, reporting an absent
    /// `keys` directory as a recoverable local-state condition instead of a
    /// bare not-found error.
    pub(crate) fn open_from_anchored_home_required(
        home: &AnchoredDir,
        owner: &MemberHandle,
    ) -> Result<Self> {
        Self::open_from_anchored_home(home)
            .map_err(|error| build_keystore_open_error(error, home, owner))
    }

    pub(crate) fn ensure_from_anchored_home(home: &AnchoredDir) -> Result<Self> {
        home.ensure_child(KEYSTORE_DIR_NAME).map(|root| Self {
            root,
            home: Some(home.clone()),
        })
    }

    pub(crate) fn root(&self) -> &Path {
        self.root.path()
    }

    /// The directory this keystore is bound to, for an identity comparison.
    pub(crate) fn root_dir(&self) -> &AnchoredDir {
        &self.root
    }

    pub(crate) fn home(&self) -> Option<&AnchoredDir> {
        self.home.as_ref()
    }

    fn from_opened(root: AnchoredDir) -> Self {
        Self { root, home: None }
    }

    /// Open one member directory of this keystore, or report that the keystore
    /// stores no member under that handle.
    ///
    /// The handle is opened with `O_DIRECTORY | O_NOFOLLOW`, so a symlink or a
    /// regular file standing under the name is refused as unsafe local state
    /// rather than passed off as an absent member. A caller only asking whether
    /// a member is there asks this rather than searching an enumeration, which
    /// cannot tell those two apart.
    pub(crate) fn open_member(&self, member: &MemberHandle) -> Result<Option<OpenDir>> {
        open_optional_child_dir(&self.root, member.as_str())
    }

    pub(super) fn ensure_member(&self, member: &MemberHandle) -> Result<OpenDir> {
        ensure_child_dir_restricted_at(&self.root, member.as_str())
    }

    pub(super) fn key_permission_chain<'a, D>(
        &'a self,
        member_dir: &'a D,
        key_dir: &'a OpenDir,
    ) -> Vec<&'a dyn DirectoryFd>
    where
        D: DirectoryFd,
    {
        let mut chain = self.member_permission_chain(member_dir);
        chain.push(key_dir);
        chain
    }

    /// Local state directory enclosing the keystore root.
    ///
    /// The enclosing directory is part of the chain no matter how the keystore
    /// was opened: a caller naming `keys/` directly still depends on the parent
    /// staying owner-only for the keys underneath to be private.
    fn home_permission_target(&self) -> Option<&OpenDir> {
        self.root.parent()
    }

    fn root_permission_chain(&self) -> Vec<&dyn DirectoryFd> {
        let mut chain: Vec<&dyn DirectoryFd> = Vec::with_capacity(2);
        if let Some(home) = self.home_permission_target() {
            chain.push(home);
        }
        chain.push(&self.root);
        chain
    }

    pub(super) fn member_permission_chain<'a, D>(
        &'a self,
        member_dir: &'a D,
    ) -> Vec<&'a dyn DirectoryFd>
    where
        D: DirectoryFd,
    {
        let mut chain = self.root_permission_chain();
        chain.push(member_dir);
        chain
    }
}

/// Open one key directory inside a member namespace already inspected by the caller.
///
/// Inspecting the namespace walks the whole member directory, so a caller that
/// has already done it enters here instead of paying for a
/// second walk that can report nothing new.
pub(super) fn open_required_key_in_verified_namespace<D>(
    member_dir: &D,
    member: &MemberHandle,
    kid: &Kid,
) -> Result<OpenDir>
where
    D: DirectoryFd,
{
    let key_dir = open_optional_child_dir(member_dir, kid.as_str())?
        .ok_or_else(|| key_not_found(member, kid))?;
    ensure_key_directory_safe(&key_dir)?;
    Ok(key_dir)
}

/// Report a context that was asked for a local keystore it does not carry.
///
/// `subject` names the operation that needs the keystore. This stays an
/// invalid-operation error because the caller only knows that the capability is
/// absent; `build_missing_keystore_error` is the variant for callers that also
/// know the keystore path and can therefore raise the actionable local-state
/// rule the CLI turns into `--home` guidance.
pub(crate) fn build_local_keystore_capability_error(subject: &str) -> Error {
    Error::build_invalid_operation_error(format!("{subject} requires a local keystore"))
}

/// Report an absent local keystore as an actionable local-state condition.
pub(crate) fn build_missing_keystore_error(keystore_path: &Path, owner: &MemberHandle) -> Error {
    Error::build_local_keystore_missing_error(format!(
        "Local keystore '{}' is required to verify the trust store for '{}'. Use --home or KAPSARO_HOME to select the local state directory.",
        format_path_relative_to_cwd(keystore_path),
        owner
    ))
}

/// Replace the not-found error of an absent `keys` directory with the
/// actionable local-keystore rule, leaving every other failure untouched.
fn build_keystore_open_error(error: Error, home: &AnchoredDir, owner: &MemberHandle) -> Error {
    if error.kind() != ErrorKind::NotFound {
        return error;
    }
    build_missing_keystore_error(&home.path().join(KEYSTORE_DIR_NAME), owner)
}

pub(super) fn key_not_found(member: &MemberHandle, kid: &Kid) -> Error {
    Error::build_not_found_error(format!("Key '{}' not found for member '{}'", kid, member))
}

/// Report a key whose directory holds only one of its two documents.
///
/// Naming the condition keeps the operator from looking for a key that `key
/// list` still shows: the key directory is there, and one of the two documents
/// it needs is gone. The kind stays the same as a key that is absent, so a
/// caller that treats a missing key as nothing to do still does nothing.
pub(super) fn key_half_missing(member: &MemberHandle, kid: &Kid) -> Error {
    Error::build_not_found_error(format!(
        "Key '{}' of member '{}' is missing one of the two key documents. \
         Restore the key directory from a backup, or remove the key with \
         'kapsaro key remove {} --member-handle {}' and generate a new one.",
        kid, member, kid, member
    ))
}

/// One level of the keystore namespace, naming what the keystore stores there.
///
/// The keystore writes member directories at its root, key directories and the
/// `active` marker inside a member, and the two key documents inside a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum KeystoreLevel {
    Root,
    Member,
    Key,
}

impl KeystoreLevel {
    /// The entry type the keystore stores under `name` at this level, if it
    /// stores one there at all.
    ///
    /// A member handle has no shape that sets it apart from an ordinary file
    /// name, so enumeration at the root cannot tell a member from a name the
    /// keystore never wrote. Claiming one there would turn a stray `notes` file
    /// into a failure of the whole keystore. A member is instead recognised
    /// when a caller names it: `open_member` opens the handle with
    /// `O_DIRECTORY | O_NOFOLLOW`, so a symlink or a file standing in its place
    /// is refused there, where the name really is the one the keystore stores.
    fn stored_type(self, name: &str) -> Option<ChildType> {
        match self {
            Self::Root => None,
            Self::Member if name == ACTIVE_FILE => Some(ChildType::RegularFile),
            Self::Member => canonical_directory_type(Kid::from_canonical(name).is_ok()),
            Self::Key => match name {
                PRIVATE_KEY_FILE | PUBLIC_KEY_FILE => Some(ChildType::RegularFile),
                _ => None,
            },
        }
    }
}

fn canonical_directory_type(is_canonical: bool) -> Option<ChildType> {
    is_canonical.then_some(ChildType::Directory)
}

/// Child directory names of a keystore directory.
/// Regular files and symlinks are never members or keys, so an entry under a
/// name the keystore does not store is skipped. An entry of any other
/// unexpected type is rejected, and so is one an unfinished write left staged.
pub(super) fn list_keystore_child_directories<D>(
    dir: &D,
    level: KeystoreLevel,
) -> Result<Vec<String>>
where
    D: DirectoryFd,
{
    let mut names = Vec::new();
    for (name, child_type) in list_child_entries_at(dir)? {
        if let Some(name) = keystore_child_directory_name(dir, level, name, child_type)? {
            names.push(name);
        }
    }
    Ok(names)
}

fn keystore_child_directory_name<D>(
    dir: &D,
    level: KeystoreLevel,
    name: String,
    child_type: ChildType,
) -> Result<Option<String>>
where
    D: DirectoryFd,
{
    if is_write_staging_name(&name) {
        return Ok(None);
    }
    ensure_keystore_entry_safe(dir, level, &name, child_type)?;
    match child_type {
        ChildType::Directory => Ok(Some(name)),
        _ => Ok(None),
    }
}

/// Fail-closed check of one canonical keystore entry before it is used.
/// Internal staging names are ignored by normal readers and reported by Doctor.
fn ensure_keystore_entry_safe<D>(
    dir: &D,
    level: KeystoreLevel,
    name: &str,
    child_type: ChildType,
) -> Result<()>
where
    D: DirectoryFd,
{
    if is_write_staging_name(name) {
        return Ok(());
    }
    match level.stored_type(name) {
        Some(stored) if stored != child_type => Err(shadowing_entry(dir, name, child_type)),
        _ if child_type == ChildType::Other => Err(unsafe_entry(dir, name, child_type)),
        _ => Ok(()),
    }
}

pub(super) fn ensure_member_namespace_safe<D>(member_dir: &D) -> Result<()>
where
    D: DirectoryFd,
{
    list_keystore_child_directories(member_dir, KeystoreLevel::Member).map(|_| ())
}

/// Complete a member mutation and re-check the namespace it changed.
///
/// The mutation result is decided first, so a namespace that also looks wrong
/// afterwards never replaces the failure the caller asked about. A namespace
/// that became unsafe after a successful mutation is reported as such, because
/// the mutation already landed. The caller names both which change that was and
/// which entry it landed on, so a removal is never reported as a write the
/// operator can go looking for, and the entry named is the one that changed
/// rather than the directory it sits in.
pub(super) fn finish_member_mutation<T, D>(
    member_dir: &D,
    changed_path: &Path,
    change: CompletedChange,
    mutation_result: Result<T>,
) -> Result<T>
where
    D: DirectoryFd,
{
    let value = mutation_result?;
    match ensure_member_namespace_safe(member_dir) {
        Ok(()) => Ok(value),
        Err(error) => Err(build_post_mutation_validation_error(
            changed_path,
            change,
            error,
        )),
    }
}

fn build_post_mutation_validation_error(
    changed_path: &Path,
    change: CompletedChange,
    error: Error,
) -> Error {
    Error::build_local_state_path_unsafe_error(format_post_change_failure(
        "The keystore entry",
        changed_path,
        change,
        "the member directory became unsafe immediately after",
        error.format_user_message(),
    ))
}

pub(super) fn unsafe_entry<D>(dir: &D, name: &str, child_type: ChildType) -> Error
where
    D: DirectoryFd,
{
    Error::build_local_state_path_unsafe_error(format!(
        "unsafe {:?} entry in keystore: {}",
        child_type,
        format_finding_path(&dir.path().join(name))
    ))
}

/// Report an entry impersonating a name the keystore stores itself. Handing out
/// what it points at would let it stand in for the member, key or document the
/// keystore wrote under that name.
fn shadowing_entry<D>(dir: &D, name: &str, child_type: ChildType) -> Error
where
    D: DirectoryFd,
{
    Error::build_local_state_path_unsafe_error(format!(
        "{:?} entry shadowing a name the keystore stores: {}",
        child_type,
        format_finding_path(&dir.path().join(name))
    ))
}

/// Fail-closed check of one key directory before its documents are opened.
/// Unknown entries are ignored as OS and tool metadata, while an entry standing
/// where a key document belongs is rejected, and so is one of an unexpected
/// type or one an unfinished write left staged.
pub(super) fn ensure_key_directory_safe(dir: &OpenDir) -> Result<()> {
    for (name, child_type) in list_child_entries_at(dir)? {
        ensure_keystore_entry_safe(dir, KeystoreLevel::Key, &name, child_type)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_keystore_access_permission_test.rs"]
mod io_keystore_access_permission_test;

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_keystore_access_security_test.rs"]
mod io_keystore_access_security_test;
