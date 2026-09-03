// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Doctor checks for CI readiness when the environment-variable key mode is active.
//! Covers strict key checking, command scope, private key loading, and CI trust caveats.

use super::types::{DoctorCategory, DoctorCheck, DoctorSubject};

/// Environment observations captured by the CLI before service execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoctorCiReadiness {
    Inactive,
    Active {
        strict_key_checking_disabled: bool,
        private_key_error: Option<String>,
    },
}

pub fn check_ci_readiness(input: DoctorCiReadiness) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    let DoctorCiReadiness::Active {
        strict_key_checking_disabled,
        private_key_error,
    } = input
    else {
        return vec![check_inactive_env_key_mode()];
    };

    checks.push(check_active_env_key_mode());
    checks.extend(check_strict_key_checking(strict_key_checking_disabled));
    checks.push(check_ci_command_scope());
    checks.push(check_env_private_key_load(private_key_error.as_deref()));
    checks.push(check_trusted_ci_context());
    checks
}

fn check_inactive_env_key_mode() -> DoctorCheck {
    DoctorCheck::skip(
        "ci.env_key.present",
        DoctorCategory::CiReadiness,
        DoctorSubject::Environment("KAPSARO_PRIVATE_KEY".to_string()),
        "Environment-variable key mode is not active",
    )
}

fn check_active_env_key_mode() -> DoctorCheck {
    DoctorCheck::ok(
        "ci.env_key.present",
        DoctorCategory::CiReadiness,
        DoctorSubject::Environment("KAPSARO_PRIVATE_KEY".to_string()),
        "Environment-variable key mode is active",
    )
}

fn check_strict_key_checking(disabled: bool) -> Vec<DoctorCheck> {
    if disabled {
        return vec![DoctorCheck::warn_with_next_action(
            "ci.strict_key_checking",
            DoctorCategory::CiReadiness,
            DoctorSubject::Environment("KAPSARO_STRICT_KEY_CHECKING".to_string()),
            "Strict key checking is disabled for read-path approval cache checks",
            "confirm this is a trusted CI context",
        )];
    }
    Vec::new()
}

fn check_ci_command_scope() -> DoctorCheck {
    DoctorCheck::ok(
        "ci.command_scope",
        DoctorCategory::CiReadiness,
        DoctorSubject::General("env-key mode".to_string()),
        "Env-key mode is restricted to read-only commands plus doctor",
    )
}

fn check_env_private_key_load(error: Option<&str>) -> DoctorCheck {
    match error {
        None => DoctorCheck::ok(
            "ci.env_key.load",
            DoctorCategory::CiReadiness,
            DoctorSubject::Environment("KAPSARO_PRIVATE_KEY".to_string()),
            "Environment private key can be loaded",
        ),
        Some(error) => DoctorCheck::fail_with_reason_and_next_action(
            "ci.env_key.load",
            DoctorCategory::CiReadiness,
            DoctorSubject::Environment("KAPSARO_PRIVATE_KEY".to_string()),
            "Environment private key could not be loaded",
            error,
            "check CI secret configuration, base64, and password",
        ),
    }
}

fn check_trusted_ci_context() -> DoctorCheck {
    DoctorCheck::warn_with_next_action(
        "ci.trusted_context",
        DoctorCategory::CiReadiness,
        DoctorSubject::General("CI platform".to_string()),
        "doctor cannot prove the CI runner, ref, or workflow is trusted",
        "review the CI workflow and protected branch settings",
    )
}
