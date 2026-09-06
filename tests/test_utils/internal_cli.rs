// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Minimal helpers for CLI internal unit tests.
//! These helpers avoid pulling the full integration-test fixture module into the library test target.

use kapsaro_core::test_support::domain::identity::MemberHandle;
// The integration binary imports the shared guard through its own facade.
#[allow(unused_imports)]
pub(crate) use kapsaro_test_support::guards::EnvGuard;

pub(crate) struct StdoutColorGuard {
    previous: bool,
}

impl StdoutColorGuard {
    pub(crate) fn new(enabled: bool) -> Self {
        let previous = console::colors_enabled();
        console::set_colors_enabled(enabled);
        Self { previous }
    }
}

impl Drop for StdoutColorGuard {
    fn drop(&mut self) {
        console::set_colors_enabled(self.previous);
    }
}

pub(crate) fn member_handle(value: impl Into<String>) -> MemberHandle {
    MemberHandle::try_from(value.into()).expect("test member_handle must be valid")
}
