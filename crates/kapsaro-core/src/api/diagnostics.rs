// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public diagnostics API for non-fatal local-state findings.
//! Re-exports the stable service contract without implementation logic.

pub use crate::service::diagnostics::{
    take_local_state_warnings, DiagnosticBatch, DiagnosticCode, DiagnosticCompleteness,
    DiagnosticTruncation, LocalStateDiagnostic,
};
