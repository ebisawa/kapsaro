// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Bulk member loaders used only by tests that build recipient sets by hand.
//! Command paths resolve members one at a time, so these live outside the production store.

use super::paths::{open_optional_members_dir, MemberStatus};
use super::store::load::{load_member_document_names_at, load_member_file, load_sorted_members};
use super::store::review_active_member_document;
use crate::model::public_key::PublicKey;
use crate::support::fs::relative::{open_dir_nofollow, DirectoryScope};
use crate::{Error, Result};
use std::path::Path;

/// Load every incoming member document, sorted by subject handle.
pub(crate) fn load_incoming_member_files(workspace_path: &Path) -> Result<Vec<PublicKey>> {
    load_sorted_members(workspace_path, MemberStatus::Incoming)
}

/// List the handles of every active member, failing when there is none.
///
/// The handles come from the document names rather than their contents, so a
/// test can build a member set out of placeholder documents.
pub(crate) fn list_active_member_handles(workspace_root: &Path) -> Result<Vec<String>> {
    let mut member_handles = match open_optional_members_dir(workspace_root, MemberStatus::Active)?
    {
        Some(dir) => load_member_document_names_at(&dir)?
            .into_iter()
            .filter_map(|name| {
                Path::new(&name)
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .map(String::from)
            })
            .collect::<Vec<_>>(),
        None => Vec::new(),
    };
    if member_handles.is_empty() {
        return Err(Error::build_not_found_error(
            "No members found in workspace".to_string(),
        ));
    }
    member_handles.sort();
    Ok(member_handles)
}

/// Load the member documents named by `member_handles`.
pub(crate) fn load_member_files(
    workspace_path: &Path,
    member_handles: &[String],
) -> Result<Vec<PublicKey>> {
    member_handles
        .iter()
        .map(|member_handle| {
            load_member_file(workspace_path, member_handle).map(|(public_key, _status)| public_key)
        })
        .collect()
}

/// Remove one active member document, addressing the workspace by path.
///
/// A command removes what its review held open, and threading that descriptor
/// through every fixture would say nothing about what these tests check. The
/// workspace is opened here instead, once, right before the removal.
pub(crate) fn remove_active_member(workspace_path: &Path, member_handle: &str) -> Result<()> {
    let workspace = open_dir_nofollow(workspace_path, DirectoryScope::Generic)?;
    review_active_member_document(&workspace, member_handle)?.remove()
}
