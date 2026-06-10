// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Artifact recipient set approval operations and integrity checks.
//! Keeps evidence extraction, record judgment, and record mutation separated.

mod evidence;
mod mutation;
mod record;

pub(crate) use evidence::{
    encrypted_content_recipient_evidence, file_content_recipient_evidence, file_recipient_evidence,
    kv_content_recipient_evidence, kv_recipient_evidence, ArtifactRecipientEvidence,
};
pub use mutation::{purge_recipient_sets, remove_recipient_set, upsert_recipient_set};
pub use record::{
    compute_recipient_set_hash, find_recipient_handle_mismatch, is_self_only_recipient_set,
    is_signer_in_recipient_set, judge_recipient_set, normalize_recipient_kids,
    validate_recipient_set_record, ArtifactRecipientSet, RecipientHandleMismatch,
    RecipientSetJudgment,
};

#[cfg(test)]
#[path = "../../../tests/unit/internal/feature_trust_recipient_sets_test.rs"]
mod feature_trust_recipient_sets_test;
