// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Application-layer KV mutation orchestration.
//! Keeps the public mutation entrypoints stable while splitting review and execution.

mod execution;
mod plan;
mod snapshot;

pub use execution::{
    import_kv_command_with_recipient_set_confirmation,
    set_kv_command_with_recipient_set_confirmation,
    unset_kv_command_with_recipient_set_confirmation,
};
pub use plan::{resolve_mutation_write_plan, MutationWriteTrustPlan};

#[cfg(test)]
#[path = "../../../tests/unit/internal/app_kv_mutation_test.rs"]
mod tests;
