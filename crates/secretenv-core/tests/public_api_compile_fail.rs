// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

#[test]
fn external_crate_cannot_reach_internal_or_opaque_facade_parts() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/public_api/default_internal_modules.rs");
    cases.compile_fail("tests/ui/public_api/flat_api_reexports.rs");
    cases.compile_fail("tests/ui/public_api/opaque_facade_internals.rs");

    #[cfg(not(feature = "cli-internal"))]
    cases.compile_fail("tests/ui/public_api/default_cli_api.rs");
}
