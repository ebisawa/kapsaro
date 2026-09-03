// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! The workspace member document store.
//! Groups the reads, writes, removals and uniqueness checks that act on members/.

pub(crate) mod load;
mod remove;
mod save;
mod uniqueness;

pub use load::{
    list_active_member_paths, list_incoming_member_paths, load_active_member_files,
    load_member_file, load_member_file_from_path, load_verified_member_file_from_path,
};
pub(crate) use load::{load_active_member_files_at, open_member_documents_at, MemberDocuments};
pub use remove::{review_active_member_document, ReviewedMemberDocument};
#[cfg(test)]
pub(crate) use remove::{set_member_post_quarantine_hook, set_member_pre_quarantine_hook};
#[cfg(test)]
pub(crate) use save::set_post_open_save_dirs_hook;
pub use save::{save_member_content, save_member_content_keeping_existing, MemberDocumentWrite};
pub(crate) use uniqueness::{
    check_workspace_member_kid_uniqueness_in_open_dirs, MemberKidCandidate,
};
