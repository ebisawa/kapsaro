// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Workspace member file I/O operations.

mod paths;
mod promotion;
mod store;

pub use paths::{get_active_member_file_path, get_incoming_member_file_path, MemberStatus};
pub use promotion::{
    promote_incoming_members, promote_snapshotted_incoming_members,
    promote_specified_incoming_members, IncomingMemberPromotionSnapshot,
};
pub use store::{
    ensure_member_document_kid_is_unique, ensure_workspace_member_kid_uniqueness,
    find_active_member_by_kid, list_active_member_handles, list_active_member_paths,
    list_incoming_member_paths, list_member_file_paths, load_active_member_files,
    load_active_member_index_by_kid, load_incoming_member_files, load_member_file,
    load_member_file_from_path, load_member_files, load_verified_member_file_from_path,
    remove_member, save_member_content,
};

#[cfg(test)]
#[path = "../../../tests/unit/internal/workspace_members_internal_test.rs"]
mod tests;
