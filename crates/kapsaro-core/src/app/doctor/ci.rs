// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::options::CommonCommandOptions;
use crate::feature::context::env_key::{is_env_key_mode, load_private_key_from_env};

use super::types::{DoctorCategory, DoctorCheck, DoctorSubject};

pub fn check_ci_readiness(options: &CommonCommandOptions) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    if !is_env_key_mode() {
        checks.push(check_inactive_env_key_mode());
        return checks;
    }

    checks.push(check_active_env_key_mode());
    checks.extend(check_strict_key_checking());
    checks.push(check_ci_command_scope());
    checks.push(check_env_private_key_load(options.debug));
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

fn check_strict_key_checking() -> Vec<DoctorCheck> {
    if std::env::var_os("KAPSARO_STRICT_KEY_CHECKING").as_deref()
        == Some(std::ffi::OsStr::new("no"))
    {
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

fn check_env_private_key_load(debug_enabled: bool) -> DoctorCheck {
    match load_private_key_from_env(debug_enabled) {
        Ok(_) => DoctorCheck::ok(
            "ci.env_key.load",
            DoctorCategory::CiReadiness,
            DoctorSubject::Environment("KAPSARO_PRIVATE_KEY".to_string()),
            "Environment private key can be loaded",
        ),
        Err(error) => DoctorCheck::fail_with_reason_and_next_action(
            "ci.env_key.load",
            DoctorCategory::CiReadiness,
            DoctorSubject::Environment("KAPSARO_PRIVATE_KEY".to_string()),
            "Environment private key could not be loaded",
            error.format_user_message(),
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
