// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public workspace registration API.
//! Re-exports the stable service contract without implementation logic.

pub use crate::service::registration::{
    ensure_init_workspace_structure, evaluate_init_workspace_status, InitWorkspaceState,
};

pub mod command {
    pub use crate::service::registration::command::{
        evaluate_registration_decision, execute_registration_decision,
        resolve_registration_command, RegistrationDecision,
    };
}

pub mod key_plan {
    pub use crate::service::registration::key_plan::{
        open_registration_local_state, RegistrationLocalState,
    };
}

pub mod types {
    pub use crate::service::registration::types::{
        MemberKeySetupResult, RegistrationCommand, RegistrationKeyPlan, RegistrationMode,
        RegistrationOutcome, RegistrationResult, RegistrationTarget,
    };
}
