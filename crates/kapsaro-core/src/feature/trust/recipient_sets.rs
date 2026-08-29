// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Artifact recipient set approval operations and integrity checks.
//! Keeps evidence extraction, record judgment, and record mutation separated.

mod evidence;
mod mutation;
mod record;

pub(crate) use evidence::{
    encrypted_content_recipient_evidence, file_recipient_evidence, kv_recipient_evidence,
    ArtifactRecipientEvidence,
};
pub use mutation::{purge_recipient_sets, remove_recipient_set, upsert_recipient_set};
pub use record::{
    find_recipient_handle_mismatch, is_self_only_recipient_set, judge_recipient_set,
    validate_recipient_set_record, ArtifactRecipientSet, RecipientHandleMismatch,
    RecipientSetJudgment,
};
// Crate code computes the hash inside `record`; this re-export exists so the
// first-party test harness can reach it through the `cli-test-support`
// allow-list, which is the only build where it has a caller.
#[cfg_attr(not(feature = "cli-test-support"), allow(unused_imports))]
pub use record::compute_recipient_set_hash;

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_trust_recipient_sets_test.rs"]
mod feature_trust_recipient_sets_test;
