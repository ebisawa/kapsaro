// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Repository-level check for the release build profile.
//! Pins the panic strategy that drop-time secret zeroization depends on.

use std::fs;
use std::path::PathBuf;

const RELEASE_PROFILE_SECTION: &str = "[profile.release]";
const UNWIND_PANIC_STRATEGY: &str = "unwind";

#[test]
fn test_release_profile_uses_unwind_panic_strategy() {
    let manifest = fs::read_to_string(workspace_manifest_path()).unwrap();

    assert_eq!(
        resolve_release_panic_strategy(&manifest),
        UNWIND_PANIC_STRATEGY,
        "release builds must unwind so Drop implementations can zeroize secrets",
    );
}

#[test]
fn test_resolve_release_panic_strategy_reads_the_release_profile() {
    let manifest = concat!(
        "[profile.dev]\n",
        "panic = \"unwind\"\n",
        "\n",
        "[profile.release]\n",
        "lto = \"fat\"\n",
        "panic = \"abort\"\n",
    );

    assert_eq!(resolve_release_panic_strategy(manifest), "abort");
}

fn workspace_manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")
}

/// Resolve the effective panic strategy of the release profile.
///
/// Cargo applies `unwind` when a profile omits the key, so an absent entry
/// resolves to the same value as an explicit one.
fn resolve_release_panic_strategy(manifest: &str) -> String {
    release_profile_lines(manifest)
        .filter_map(|line| line.strip_prefix("panic"))
        .filter_map(|rest| rest.trim_start().strip_prefix('='))
        .map(|value| value.trim().trim_matches('"').to_owned())
        .next()
        .unwrap_or_else(|| UNWIND_PANIC_STRATEGY.to_owned())
}

fn release_profile_lines(manifest: &str) -> impl Iterator<Item = &str> {
    manifest
        .lines()
        .map(str::trim)
        .skip_while(|line| *line != RELEASE_PROFILE_SECTION)
        .skip(1)
        .take_while(|line| !line.starts_with('['))
}
