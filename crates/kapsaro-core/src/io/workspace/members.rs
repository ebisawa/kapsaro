// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Workspace member file I/O operations.

mod paths;
mod promotion;
mod store;

pub use paths::{get_active_member_file_path, get_incoming_member_file_path, MemberStatus};
pub(crate) use paths::{
    has_member_document_extension, ACTIVE_DIR_NAME, INCOMING_DIR_NAME, MEMBERS_DIR_NAME,
};
pub use promotion::{
    capture_promotion_destination_at, promote_snapshotted_incoming_members_at,
    IncomingMemberPromotionSnapshot, PromotionDestinationState,
};
pub use store::{
    list_active_member_paths, list_incoming_member_paths, load_active_member_files,
    load_member_file, load_member_file_from_path, load_verified_member_file_from_path,
    review_active_member_document, save_member_content, save_member_content_keeping_existing,
    MemberDocumentWrite, ReviewedMemberDocument,
};
pub(crate) use store::{load_active_member_files_at, open_member_documents_at, MemberDocuments};
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
#[path = "../../../tests/unit/internal/workspace_members_internal_test.rs"]
mod internal_tests;

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_member_test.rs"]
mod feature_member_test;

#[cfg(test)]
#[path = "../../../tests/unit/internal/workspace_members_test.rs"]
mod workspace_members_test;
