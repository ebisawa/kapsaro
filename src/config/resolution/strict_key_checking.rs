// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! SECRETENV_STRICT_KEY_CHECKING environment variable resolution.

use crate::config::types::{ResolvedStrictKeyChecking, StrictKeyChecking, StrictKeyCheckingSource};

const ENV_VAR: &str = "SECRETENV_STRICT_KEY_CHECKING";

/// Resolve strict key checking from the environment variable.
///
/// Values: "yes" (default), "no" (case-insensitive).
pub(crate) fn resolve_strict_key_checking() -> ResolvedStrictKeyChecking {
    match std::env::var(ENV_VAR) {
        Ok(val) if val.eq_ignore_ascii_case("no") => {
            ResolvedStrictKeyChecking::explicit(StrictKeyChecking::No)
        }
        Ok(val) if val.eq_ignore_ascii_case("yes") => ResolvedStrictKeyChecking {
            mode: StrictKeyChecking::Yes,
            source: StrictKeyCheckingSource::ExplicitEnv,
        },
        _ => ResolvedStrictKeyChecking::strict(),
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/config_resolution_strict_key_checking_test.rs"]
mod tests;
