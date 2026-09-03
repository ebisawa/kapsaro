// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public local and workspace diagnostics API.
//! Re-exports the stable service contract without implementation logic.

pub use crate::service::doctor::ci::DoctorCiReadiness;
pub use crate::service::doctor::{
    execute_doctor_command, DoctorRequest, DoctorWorkspaceResolution, DoctorWorkspaceSource,
};

pub mod types {
    pub use crate::service::doctor::types::{
        DoctorCategory, DoctorCheck, DoctorReason, DoctorReport, DoctorStatus, DoctorSubject,
    };
}
