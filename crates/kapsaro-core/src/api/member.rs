// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public workspace member API.
//! Re-exports the stable service contract without implementation logic.

pub mod approval {
    pub use crate::service::member::approval::{
        evaluate_members_for_approval, save_member_approvals, MemberApprovalEvaluation,
        MemberApprovalResult, MemberApprovalSession,
    };
}

pub mod mutation {
    pub use crate::service::member::mutation::{
        add_member, evaluate_member_removal, remove_member,
    };
}

pub mod query {
    pub use crate::service::member::query::{list_members, load_member_show_result};
}

pub mod types {
    pub use crate::service::member::types::{
        MemberDocumentStatus, MemberDocumentView, MemberGithubClaim, MemberListEntry,
        MemberListResult, MemberRemovalReport, MemberRemoveResult, MemberShowResult,
        MemberVerificationResult, MembershipStatus,
    };
}

pub mod verification {
    pub use crate::service::member::verification::verify_members;
}
