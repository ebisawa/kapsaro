// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Immutable trust snapshots for a single command execution.
//! Re-exports context, workspace, and write-plan units through the existing path.

mod context;
mod workspace;
mod write;

pub use context::{load_read_trust_context, ReadTrustContextLoadResult, TrustContext};
pub use workspace::WorkspaceMemberSnapshot;
// Production builds the snapshot inside `WriteRecipientTrustPlan`; the type is
// re-exported so the snapshot tests can load one on its own.
#[cfg(test)]
pub(crate) use write::CommandTrustSnapshot;
pub use write::WriteRecipientTrustPlan;
