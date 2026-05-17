// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn cli_uses_cli_api_for_core_internal_access() {
    let cli_files = collect_rust_files(Path::new("src/cli"));
    assert!(!cli_files.is_empty(), "expected CLI source files");

    let forbidden = internal_core_paths("secretenv_core");

    let violations = cli_files
        .iter()
        .flat_map(|path| {
            let content = fs::read_to_string(path).expect("read CLI source");
            let aliases = collect_core_aliases(&content);
            let patterns = forbidden
                .iter()
                .cloned()
                .chain(
                    aliases
                        .iter()
                        .flat_map(|alias| internal_core_paths(alias.as_str())),
                )
                .collect::<Vec<_>>();
            patterns
                .into_iter()
                .filter(move |pattern| content.contains(pattern.as_str()))
                .map(move |pattern| format!("{} contains {}", path.display(), pattern))
        })
        .collect::<Vec<_>>();

    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

#[test]
fn cli_does_not_use_broad_cli_api_reexports() {
    let cli_files = collect_rust_files(Path::new("src/cli"));
    assert!(!cli_files.is_empty(), "expected CLI source files");

    let forbidden = broad_cli_api_paths("secretenv_core");

    let violations = cli_files
        .iter()
        .flat_map(|path| {
            let content = fs::read_to_string(path).expect("read CLI source");
            let aliases = collect_core_aliases(&content);
            let patterns = forbidden
                .iter()
                .cloned()
                .chain(
                    aliases
                        .iter()
                        .flat_map(|alias| broad_cli_api_paths(alias.as_str())),
                )
                .collect::<Vec<_>>();
            patterns
                .into_iter()
                .filter(move |pattern| content.contains(pattern.as_str()))
                .map(move |pattern| format!("{} contains {}", path.display(), pattern))
        })
        .collect::<Vec<_>>();

    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

#[test]
fn cli_api_does_not_reexport_internal_bridge_or_wildcard_modules() {
    let content =
        fs::read_to_string("crates/secretenv-core/src/cli_api.rs").expect("read cli_api source");
    let production_app = content
        .split("#[cfg(any(feature = \"cli-test-support\", test))]")
        .next()
        .expect("production cli_api app");
    let forbidden = [
        "pub mod internal",
        "\npub mod config",
        "\npub mod crypto",
        "\npub mod feature",
        "\npub mod format",
        "\npub mod io",
        "\npub mod model",
        "\npub mod support",
        "pub mod content",
        "pub use crate::format::content::FileEncContent",
        "pub use crate::support::fs::{atomic",
        "pub use crate::app::*",
        "pub use crate::feature::*",
        "pub use crate::support::tty::*",
        "pub use crate::support::validation::*",
    ];
    let violations = forbidden
        .iter()
        .filter(|pattern| production_app.contains(**pattern))
        .copied()
        .collect::<Vec<_>>();

    assert!(violations.is_empty(), "{}", violations.join("\n"));
    assert!(!production_app.contains("pub use crate::app::{"));
}

#[test]
fn cli_api_test_support_is_hidden_and_feature_gated() {
    let content =
        fs::read_to_string("crates/secretenv-core/src/cli_api.rs").expect("read cli_api source");
    let test_support = test_support_section(&content);

    assert!(content.contains("#[cfg(any(feature = \"cli-test-support\", test))]"));
    assert!(content.contains("pub mod test_support {"));
    assert!(!content.contains("pub mod internal"));
    assert!(!content.contains("pub use crate::config::*"));
    assert!(!content.contains("pub use crate::crypto::*"));
    assert!(!content.contains("pub use crate::feature::*"));
    assert!(!content.contains("pub use crate::format::*"));
    assert!(!content.contains("pub use crate::io::*"));
    assert!(!content.contains("pub use crate::model::*"));
    assert!(!content.contains("pub use crate::support::*"));
    assert!(!content.contains("pub use crate::config::types;"));

    for old_root in [
        "\n    pub mod config {",
        "\n    pub mod crypto {",
        "\n    pub mod feature {",
        "\n    pub mod format {",
        "\n    pub mod io {",
        "\n    pub mod model {",
        "\n    pub mod support {",
    ] {
        assert!(
            !test_support.contains(old_root),
            "test_support still exposes old root: {old_root}"
        );
    }

    for new_root in [
        "pub mod settings {",
        "pub mod primitives {",
        "pub mod operations {",
        "pub mod wire {",
        "pub mod storage {",
        "pub mod domain {",
        "pub mod helpers {",
    ] {
        assert!(
            test_support.contains(new_root),
            "test_support is missing redesigned root: {new_root}"
        );
    }

    let wildcard_reexports = test_support
        .lines()
        .filter(|line| line.trim_start().starts_with("pub use crate::"))
        .filter(|line| line.contains("::*"))
        .map(str::trim)
        .collect::<Vec<_>>();
    assert!(
        wildcard_reexports.is_empty(),
        "test_support uses wildcard re-exports:\n{}",
        wildcard_reexports.join("\n")
    );
}

#[test]
fn cli_api_uses_explicit_allow_lists() {
    let content =
        fs::read_to_string("crates/secretenv-core/src/cli_api.rs").expect("read cli_api source");

    assert!(content.contains("pub mod context {"));
    assert!(content.contains("pub mod file {"));
    assert!(content.contains("pub mod kv {"));
    assert!(content.contains("pub mod trust {"));
    assert!(content.contains("pub mod presentation {"));
    assert!(content.contains("pub mod file_content {"));
    assert!(content.contains("detect_file_enc_content_with_source"));
    assert!(content.contains("pub use crate::support::fs::atomic::{save_bytes, save_text};"));
    assert!(content.contains("pub mod test_support {"));
    assert!(content.contains("pub mod app {"));
}

#[test]
fn root_crate_does_not_reexport_core_facades() {
    let content = fs::read_to_string("src/lib.rs").expect("read root lib source");

    assert!(content.contains("pub mod cli;"));
    assert!(!content.contains("pub use secretenv_core::{api"));
    assert!(!content.contains("pub use secretenv_core::{"));
    assert!(!content.contains("pub use secretenv_core::api"));
    assert!(!content.contains("pub use secretenv_core::prelude"));
}

fn collect_rust_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_rust_files_into(root, &mut files);
    files.sort();
    files
}

fn collect_core_aliases(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            line.strip_prefix("use secretenv_core as ")
                .and_then(|rest| rest.strip_suffix(';'))
                .or_else(|| {
                    line.strip_prefix("extern crate secretenv_core as ")
                        .and_then(|rest| rest.strip_suffix(';'))
                })
        })
        .map(str::trim)
        .map(ToOwned::to_owned)
        .collect()
}

fn internal_core_paths(root: &str) -> Vec<String> {
    [
        "app", "config", "crypto", "feature", "format", "internal", "io", "model", "support",
    ]
    .into_iter()
    .map(|module| format!("{root}::{module}::"))
    .collect()
}

fn broad_cli_api_paths(root: &str) -> Vec<String> {
    [
        format!("{root}::cli_api::config::"),
        format!("{root}::cli_api::crypto::"),
        format!("{root}::cli_api::feature::"),
        format!("{root}::cli_api::format::"),
        format!("{root}::cli_api::io::"),
        format!("{root}::cli_api::model::"),
        format!("{root}::cli_api::support::"),
        format!("{root}::cli_api::test_support::"),
        format!("{root}::cli_api::test_support::settings::"),
        format!("{root}::cli_api::test_support::primitives::"),
        format!("{root}::cli_api::test_support::operations::"),
        format!("{root}::cli_api::test_support::wire::"),
        format!("{root}::cli_api::test_support::storage::"),
        format!("{root}::cli_api::test_support::domain::"),
        format!("{root}::cli_api::test_support::helpers::"),
        format!("{root}::cli_api::test_support;"),
        format!("{root}::cli_api::{{test_support"),
        format!("{root}::cli_api::{{ app, test_support"),
        format!("{root}::cli_api::{{ presentation, test_support"),
    ]
    .into()
}

fn test_support_section(content: &str) -> &str {
    content
        .split("#[cfg(any(feature = \"cli-test-support\", test))]")
        .nth(1)
        .expect("test_support cfg section")
}

fn collect_rust_files_into(path: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(path).expect("read source directory") {
        let entry = entry.expect("read source entry");
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files_into(&path, files);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            files.push(path);
        }
    }
}
