// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared decision for tests that stage a permission denial and need it to bite.
//! Root passes every permission check, so such a test is skipped or refused there.

#![cfg(unix)]

/// Set this in an environment that is expected to run tests unprivileged, and a
/// privileged run fails instead of skipping the permission checks in silence.
pub const REQUIRE_UNPRIVILEGED_ENV: &str = "KAPSARO_TEST_REQUIRE_UNPRIVILEGED";

/// What a test that stages a permission denial should do in this process.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PrivilegeVerdict {
    /// The denial can be arranged, so the test runs.
    Available,
    /// The denial cannot be arranged here, and the environment tolerates that.
    Skipped,
    /// The denial cannot be arranged here, and the environment asked that it be.
    Refused,
}

/// Decide what a test staging a permission denial should do, from the effective
/// uid and whether the environment requires an unprivileged run.
///
/// The decision is kept apart from the process it describes so every outcome can
/// be exercised from an ordinary unprivileged test run.
///
/// This looks at the effective uid alone. A non-root user holding
/// `CAP_DAC_OVERRIDE` bypasses the same permission checks root does, and this
/// function has no way to see that capability: it still returns `Available`,
/// so a test staging a denial under such a user fails to see the denial bite
/// rather than being skipped or refused the way a root run is.
pub fn judge_privilege(effective_uid: u32, unprivileged_required: bool) -> PrivilegeVerdict {
    if effective_uid != 0 {
        return PrivilegeVerdict::Available;
    }
    if unprivileged_required {
        PrivilegeVerdict::Refused
    } else {
        PrivilegeVerdict::Skipped
    }
}

/// Whether this process can arrange the permission denial `test_name` needs.
///
/// Returns false after reporting the skip when the run is privileged and the
/// environment tolerates it, and panics when the environment asked for an
/// unprivileged run and got a privileged one.
pub fn permission_denial_can_be_staged(test_name: &str) -> bool {
    let effective_uid = rustix::process::geteuid().as_raw();
    let unprivileged_required = std::env::var_os(REQUIRE_UNPRIVILEGED_ENV).is_some();
    match judge_privilege(effective_uid, unprivileged_required) {
        PrivilegeVerdict::Available => true,
        PrivilegeVerdict::Skipped => {
            eprintln!(
                "skipping {test_name}: root passes every permission check, so the denial \
                 this test stages cannot be arranged in a privileged process. Set \
                 {REQUIRE_UNPRIVILEGED_ENV} to fail here instead of skipping."
            );
            false
        }
        PrivilegeVerdict::Refused => panic!(
            "{test_name} never checked what it was written to check: {REQUIRE_UNPRIVILEGED_ENV} \
             is set, yet this process runs as root, where every permission check passes."
        ),
    }
}
