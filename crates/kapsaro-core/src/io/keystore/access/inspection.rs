// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Enumeration of the keystore namespace.
//! Lists members and keys, skipping entries that are neither.

use super::{
    ensure_keystore_entry_safe, read_keystore_child_directories, KeystoreAccess, KeystoreLevel,
};
use crate::model::identity::{Kid, MemberHandle};
use crate::support::fs::lock::{with_shared_locked_directory, ReadLockedDirectory};
use crate::support::fs::relative::{list_child_entries_at, ChildType};
use crate::Result;

#[cfg(test)]
#[path = "../../../../tests/unit/internal/keystore_access_members_test.rs"]
mod keystore_access_members_test;

impl KeystoreAccess {
    pub(crate) fn list_members(&self) -> Result<Vec<MemberHandle>> {
        Ok(
            read_keystore_child_directories(&self.root, KeystoreLevel::Root)?
                .into_iter()
                .filter_map(|name| parse_stored_member_handle(&name))
                .collect(),
        )
    }

    /// Entries in the keystore root that member enumeration ignores.
    ///
    /// Safety is settled by the same check the reading paths use, so an entry
    /// this refuses cannot be listed here as merely ignored. What remains is
    /// the judgment this function owns: which safe entry is passed over.
    pub(crate) fn list_ignored_root_entries(&self) -> Result<Vec<String>> {
        let mut ignored = Vec::new();
        for (name, child_type) in list_child_entries_at(&self.root)? {
            ensure_keystore_entry_safe(&self.root, KeystoreLevel::Root, &name, child_type)?;
            if is_ignored_root_entry(&name, child_type) {
                ignored.push(name);
            }
        }
        Ok(ignored)
    }

    pub(crate) fn list_kids(&self, member: &MemberHandle) -> Result<Vec<Kid>> {
        let Some(member_dir) = self.open_member(member)? else {
            return Ok(Vec::new());
        };
        with_shared_locked_directory(&member_dir, |locked_member_dir| {
            list_kids_locked(locked_member_dir)
        })
    }
}

fn parse_stored_member_handle(name: &str) -> Option<MemberHandle> {
    MemberHandle::try_from(name).ok()
}

/// Whether member enumeration passes an entry over.
///
/// Dot-prefixed names are omitted as OS and tool metadata. Anything that is not
/// a directory holding a member handle is listed so an operator running
/// diagnostics can see the name that will never be read as a member. The caller
/// has already refused every entry type the keystore never stores, so what
/// arrives here is a directory, a regular file or a symlink.
fn is_ignored_root_entry(name: &str, child_type: ChildType) -> bool {
    if name.starts_with('.') {
        return false;
    }
    match child_type {
        ChildType::Directory => parse_stored_member_handle(name).is_none(),
        _ => true,
    }
}

pub(super) fn list_kids_locked<D>(member_dir: &D) -> Result<Vec<Kid>>
where
    D: ReadLockedDirectory,
{
    Ok(
        read_keystore_child_directories(member_dir, KeystoreLevel::Member)?
            .into_iter()
            .filter_map(|name| Kid::from_canonical(name).ok())
            .collect(),
    )
}
