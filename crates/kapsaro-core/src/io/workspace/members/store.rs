// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod load;
mod remove;
mod save;
mod uniqueness;

pub(crate) use load::load_json_files_in_dir;
pub use load::{
    list_active_member_handles, list_active_member_paths, list_incoming_member_paths,
    load_active_member_files, load_incoming_member_files, load_member_file,
    load_member_file_from_path, load_member_files, load_verified_member_file_from_path,
};
pub use remove::remove_member;
pub use save::save_member_content;
pub(crate) use uniqueness::{
    check_workspace_member_kid_uniqueness, check_workspace_member_kid_uniqueness_in_open_dirs,
    MemberKidCandidate,
};
pub use uniqueness::{
    ensure_member_document_kid_is_unique, ensure_workspace_member_kid_uniqueness,
};
