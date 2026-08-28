// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Tests for the privilege decision shared by tests that stage a permission denial.
//! Covers every combination of effective uid and the require-unprivileged request.

#![cfg(unix)]

use kapsaro_test_support::privilege::{judge_privilege, PrivilegeVerdict};

/// An unprivileged process is denied by the permission bits it sets, so the
/// denial the test needs can be arranged and the test runs.
#[test]
fn test_unprivileged_user_can_stage_a_permission_denial() {
    assert_eq!(judge_privilege(1000, false), PrivilegeVerdict::Available);
}

/// Requiring an unprivileged run changes nothing for a process that already is
/// one: the requirement is met, so the test still runs.
#[test]
fn test_unprivileged_user_meets_the_unprivileged_requirement() {
    assert_eq!(judge_privilege(1000, true), PrivilegeVerdict::Available);
}

/// Root passes every permission check, so a developer running privileged is
/// told the check cannot be arranged instead of watching it pass vacuously.
#[test]
fn test_root_without_the_requirement_is_skipped() {
    assert_eq!(judge_privilege(0, false), PrivilegeVerdict::Skipped);
}

/// A run that asked for an unprivileged environment and got root instead is a
/// failure, so a privileged CI container cannot report a green permission suite.
#[test]
fn test_root_under_the_requirement_is_refused() {
    assert_eq!(judge_privilege(0, true), PrivilegeVerdict::Refused);
}
