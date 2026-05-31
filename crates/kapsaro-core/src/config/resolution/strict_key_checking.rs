// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! KAPSARO_STRICT_KEY_CHECKING environment variable resolution.

use crate::config::types::{
    StrictKeyChecking, StrictKeyCheckingResolution, StrictKeyCheckingSource,
};

const ENV_VAR: &str = "KAPSARO_STRICT_KEY_CHECKING";

/// Resolve strict key checking from the environment variable.
///
/// Values: "yes" (default), "no" (case-insensitive).
pub(crate) fn resolve_strict_key_checking() -> StrictKeyCheckingResolution {
    match std::env::var(ENV_VAR) {
        Ok(val) if val.eq_ignore_ascii_case("no") => {
            StrictKeyCheckingResolution::explicit(StrictKeyChecking::No)
        }
        Ok(val) if val.eq_ignore_ascii_case("yes") => StrictKeyCheckingResolution {
            mode: StrictKeyChecking::Yes,
            source: StrictKeyCheckingSource::ExplicitEnv,
        },
        _ => StrictKeyCheckingResolution::strict(),
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/internal/config_resolution_strict_key_checking_test.rs"]
mod tests;
