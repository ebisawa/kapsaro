// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Guards for commands that are unavailable in environment-variable key mode.

use crate::cli::common::context::CliContext;
use crate::cli::CommandCapability;
use kapsaro_core::api::secret::SecretString;
use kapsaro_core::api::trust::StrictKeyChecking;
use kapsaro_core::api::{doctor::DoctorCiReadiness, key::load_environment_key};
use kapsaro_core::Result;
use tracing::debug;

pub(crate) fn ensure_env_mode_command_allowed(capability: CommandCapability) -> Result<()> {
    if !is_environment_key_mode() {
        debug!("[CLI] env-key mode inactive");
        return Ok(());
    }

    if capability.allows_env_key_mode() {
        debug!("[CLI] env-key mode allowed for {}", capability.label());
        return Ok(());
    }

    debug!("[CLI] env-key mode rejected for {}", capability.label());
    Err(kapsaro_core::Error::build_invalid_operation_error(format!(
        "Command unavailable in environment-variable key mode.\n\
             Command: {}\n\
             Supported commands: run, decrypt, get, list, doctor.",
        capability.label()
    )))
}

pub(crate) fn is_environment_key_mode() -> bool {
    std::env::var_os("KAPSARO_PRIVATE_KEY").is_some()
}

pub(crate) fn capture_doctor_ci_readiness(context: &CliContext) -> DoctorCiReadiness {
    if !is_environment_key_mode() {
        return DoctorCiReadiness::Inactive;
    }
    let _cleanup = EnvironmentKeyCleanup;
    let strict_key_checking = context.strict_key_checking();
    let private_key_error = validate_environment_from_cli()
        .err()
        .map(|error| error.format_user_message().to_string());
    match strict_key_checking {
        Ok(resolution) => DoctorCiReadiness::active(
            matches!(resolution.mode, StrictKeyChecking::Yes),
            private_key_error,
        ),
        Err(error) => DoctorCiReadiness::active_with_invalid_strict_key_checking(
            error.format_user_message().to_string(),
            private_key_error,
        ),
    }
}

fn validate_environment_from_cli() -> Result<()> {
    let encoded = load_secret_environment("KAPSARO_PRIVATE_KEY", false)?;
    let password = load_secret_environment("KAPSARO_KEY_PASSWORD", true)?;
    load_environment_key(encoded, password)
}

fn load_secret_environment(name: &str, password: bool) -> Result<SecretString> {
    std::env::var(name)
        .map(SecretString::new)
        .map_err(|error| match error {
            std::env::VarError::NotPresent if password => kapsaro_core::Error::build_config_error(
                format!("{name} environment variable is required when KAPSARO_PRIVATE_KEY is set"),
            ),
            std::env::VarError::NotPresent => kapsaro_core::Error::build_config_error(format!(
                "{name} environment variable is not set"
            )),
            std::env::VarError::NotUnicode(_) => kapsaro_core::Error::build_config_error(format!(
                "{name} environment variable contains invalid UTF-8"
            )),
        })
}

struct EnvironmentKeyCleanup;

impl Drop for EnvironmentKeyCleanup {
    fn drop(&mut self) {
        std::env::remove_var("KAPSARO_PRIVATE_KEY");
        std::env::remove_var("KAPSARO_KEY_PASSWORD");
    }
}
