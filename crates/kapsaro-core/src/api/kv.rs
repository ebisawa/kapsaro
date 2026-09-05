// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public kv-enc artifact API.
//! Re-exports the stable service contract without implementation logic.

pub use crate::service::kv::{
    is_missing_key_error, load_import_text, resolve_kv_store_file_name, AuthorizedKvMutation,
    KvDisclosedEntry, KvEncArtifact, KvGetResult, KvInputEntry, KvMutationOperation,
    KvReadOperation, TrustedKvEncArtifact, VerifiedKvEncArtifact,
};

pub mod mutation {
    pub use crate::service::kv::mutation::{
        import_kv_command_with_recipient_set_confirmation,
        reevaluate_mutation_write_plan_after_review, resolve_mutation_write_plan,
        set_kv_command_with_recipient_set_confirmation,
        unset_kv_command_with_recipient_set_confirmation, MutationWriteTrustPlan,
    };
}
