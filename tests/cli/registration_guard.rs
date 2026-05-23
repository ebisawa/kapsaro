// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Registration guard for manually wired CLI integration test modules.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const TOP_LEVEL_EXCLUDED: &[&str] = &["common.rs", "registration_guard.rs"];

#[test]
fn cli_top_level_test_modules_are_registered_once() {
    let root = repo_root();
    let cli_dir = root.join("tests/cli");
    let files = collect_module_files(&cli_dir, TOP_LEVEL_EXCLUDED);
    let registrations = collect_mod_registrations(&root.join("tests/cli.rs"), None)
        .into_iter()
        .filter(|(module, _)| !matches!(module.as_str(), "common.rs" | "registration_guard.rs"))
        .collect();

    assert_registered_once(&files, &registrations);
}

#[test]
fn cli_nested_test_modules_are_registered_once() {
    let root = repo_root();
    for group in ["encrypt", "init", "key", "kv", "rewrap"] {
        let files = collect_module_files(&root.join("tests/cli").join(group), &[]);
        let registrations = collect_mod_registrations(
            &root.join("tests/cli").join(format!("{group}.rs")),
            Some(group),
        );

        assert_registered_once(&files, &registrations);
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn collect_module_files(root: &Path, excluded: &[&str]) -> BTreeSet<String> {
    fs::read_dir(root)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .filter_map(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .filter(|name| !excluded.contains(&name.as_str()))
        .collect()
}

fn collect_mod_registrations(path: &Path, path_prefix: Option<&str>) -> BTreeMap<String, usize> {
    let content = fs::read_to_string(path).unwrap();
    let mut registrations = BTreeMap::new();

    for target in collect_path_attribute_targets(&content, path_prefix) {
        increment_count(&mut registrations, target);
    }
    for target in collect_inline_mod_targets(&content) {
        increment_count(&mut registrations, target);
    }

    registrations
}

fn collect_path_attribute_targets(content: &str, path_prefix: Option<&str>) -> Vec<String> {
    content
        .lines()
        .filter_map(|line| line.trim().strip_prefix("#[path = \""))
        .filter_map(|line| line.strip_suffix("\"]"))
        .filter_map(|target| match path_prefix {
            Some(prefix) => target
                .strip_prefix(&format!("{prefix}/"))
                .map(str::to_string),
            None => Some(target.to_string()),
        })
        .collect()
}

fn collect_inline_mod_targets(content: &str) -> Vec<String> {
    let mut targets = Vec::new();
    let mut has_path_attribute = false;

    for line in content.lines().map(str::trim) {
        if line.starts_with("#[path = \"") {
            has_path_attribute = true;
            continue;
        }

        if has_path_attribute {
            has_path_attribute = false;
            continue;
        }

        if let Some(module) = line
            .strip_prefix("mod ")
            .or_else(|| line.strip_prefix("pub mod "))
            .and_then(|line| line.strip_suffix(';'))
        {
            targets.push(format!("{module}.rs"));
        }
    }

    targets
}

fn increment_count(counts: &mut BTreeMap<String, usize>, path: String) {
    *counts.entry(path).or_default() += 1;
}

fn assert_registered_once(files: &BTreeSet<String>, registrations: &BTreeMap<String, usize>) {
    let registered: BTreeSet<_> = registrations.keys().cloned().collect();
    let missing: Vec<_> = files.difference(&registered).collect();
    let extra: Vec<_> = registered.difference(files).collect();
    let duplicates: Vec<_> = registrations
        .iter()
        .filter(|(_, count)| **count != 1)
        .collect();

    assert!(
        missing.is_empty(),
        "missing test registrations: {missing:?}"
    );
    assert!(extra.is_empty(), "stale test registrations: {extra:?}");
    assert!(
        duplicates.is_empty(),
        "duplicate test registrations: {duplicates:?}"
    );
}
