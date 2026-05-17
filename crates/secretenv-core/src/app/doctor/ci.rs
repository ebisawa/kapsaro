// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::options::CommonCommandOptions;
use crate::feature::context::env_key::{is_env_key_mode, load_private_key_from_env};

use super::types::{DoctorCategory, DoctorCheck, DoctorSubject};

pub fn check_ci_readiness(options: &CommonCommandOptions) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    if !is_env_key_mode() {
        checks.push(DoctorCheck::skip(
            "ci.env_key.present",
            DoctorCategory::CiReadiness,
            DoctorSubject::Environment("SECRETENV_PRIVATE_KEY".to_string()),
            "Environment-variable key mode is not active",
        ));
        return checks;
    }

    checks.push(DoctorCheck::ok(
        "ci.env_key.present",
        DoctorCategory::CiReadiness,
        DoctorSubject::Environment("SECRETENV_PRIVATE_KEY".to_string()),
        "Environment-variable key mode is active",
    ));
    if std::env::var_os("SECRETENV_STRICT_KEY_CHECKING").as_deref()
        == Some(std::ffi::OsStr::new("no"))
    {
        checks.push(
            DoctorCheck::warn(
                "ci.strict_key_checking",
                DoctorCategory::CiReadiness,
                DoctorSubject::Environment("SECRETENV_STRICT_KEY_CHECKING".to_string()),
                "Strict key checking is disabled for read-path approval cache checks",
            )
            .with_next_action("confirm this is a trusted CI context"),
        );
    }
    checks.push(DoctorCheck::ok(
        "ci.command_scope",
        DoctorCategory::CiReadiness,
        DoctorSubject::General("env-key mode".to_string()),
        "Env-key mode is restricted to read-only commands plus doctor",
    ));

    match load_private_key_from_env(options.debug) {
        Ok(_) => checks.push(DoctorCheck::ok(
            "ci.env_key.load",
            DoctorCategory::CiReadiness,
            DoctorSubject::Environment("SECRETENV_PRIVATE_KEY".to_string()),
            "Environment private key can be loaded",
        )),
        Err(error) => checks.push(
            DoctorCheck::fail(
                "ci.env_key.load",
                DoctorCategory::CiReadiness,
                DoctorSubject::Environment("SECRETENV_PRIVATE_KEY".to_string()),
                "Environment private key could not be loaded",
            )
            .with_reason(error.format_user_message())
            .with_next_action("check CI secret configuration, base64, and password"),
        ),
    }
    checks.push(
        DoctorCheck::warn(
            "ci.trusted_context",
            DoctorCategory::CiReadiness,
            DoctorSubject::General("CI platform".to_string()),
            "doctor cannot prove the CI runner, ref, or workflow is trusted",
        )
        .with_next_action("review the CI workflow and protected branch settings"),
    );
    checks
}
