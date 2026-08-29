// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer KV mutation orchestration.
//! Keeps the public mutation entrypoints stable while splitting review and execution.

mod execution;
mod plan;
mod snapshot;

// Counter and hooks below are the test seams defined in `execution`; they are
// re-exported so the mutation tests can observe and interrupt the write window.
#[cfg(test)]
pub(crate) use execution::{authorized_mutation_count, reset_authorized_mutation_count};
pub use execution::{
    import_kv_command_with_recipient_set_confirmation,
    set_kv_command_with_recipient_set_confirmation,
    unset_kv_command_with_recipient_set_confirmation,
};
#[cfg(test)]
pub(crate) use execution::{set_post_authorized_mutation_hook, set_post_recipient_approval_hook};
pub use plan::{
    reevaluate_mutation_write_plan_after_review, resolve_mutation_write_plan,
    MutationWriteTrustPlan,
};

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_kv_mutation_test.rs"]
mod tests;
