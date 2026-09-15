// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Workspace member file I/O operations.

mod paths;
mod promotion;
mod store;

pub use paths::MemberStatus;
pub(crate) use paths::{ACTIVE_DIR_NAME, INCOMING_DIR_NAME, MEMBERS_DIR_NAME};
pub use promotion::{
    capture_promotion_destination_at, promote_snapshotted_incoming_members_at,
    IncomingMemberPromotionSnapshot, PromotionDestinationState,
};
pub(crate) use store::MemberWriteStore;
#[cfg(test)]
pub(crate) use store::{
    list_active_member_paths, load_member_file, load_verified_member_file_from_path,
    save_member_content_keeping_existing,
};
#[cfg(any(test, feature = "cli-test-support"))]
pub use store::{load_active_member_files, load_member_file_from_path};
pub(crate) use store::{load_active_member_files_at, open_member_documents_at, MemberDocuments};
pub use store::{
    review_active_member_document, save_member_content, MemberDocumentWrite, ReviewedMemberDocument,
};
#[cfg(test)]
pub(crate) use store::{
    set_member_post_quarantine_hook, set_member_pre_quarantine_hook, set_post_open_save_dirs_hook,
};

// Bulk loaders that no command path uses; the tests that build member sets by
// hand reach them here rather than through the production store.
#[cfg(test)]
#[path = "../../../tests/test_support/workspace_members.rs"]
pub(crate) mod test_support;

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_workspace_members_internal_test.rs"]
mod io_workspace_members_internal_test;

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_workspace_members_removal_test.rs"]
mod io_workspace_members_removal_test;

#[cfg(test)]
#[path = "../../../tests/unit/internal/io_workspace_members_test.rs"]
mod io_workspace_members_test;
