// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const EXTERNAL_PREFIX: &str = "unit/external/";
const INTERNAL_PREFIX: &str = "tests/unit/internal/";

#[test]
fn test_unit_external_files_are_registered_once() {
    let root = repo_root();
    let external_files = collect_test_files(&root.join("tests/unit/external"));
    let registrations = collect_unit_harness_paths(&root.join("tests/unit.rs"));

    assert_registered_once(&external_files, &registrations);
}

#[test]
fn test_unit_internal_files_are_registered_once() {
    let root = repo_root();
    let internal_files = collect_test_files(&root.join("tests/unit/internal"));
    let registrations = collect_internal_harness_paths(&[root.join("src")]);

    assert_registered_once(&internal_files, &registrations);

    let core_internal_files =
        collect_test_files(&root.join("crates/secretenv-core/tests/unit/internal"));
    let core_registrations =
        collect_internal_harness_paths(&[root.join("crates/secretenv-core/src")]);

    assert_registered_once(&core_internal_files, &core_registrations);
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn collect_test_files(root: &Path) -> BTreeSet<String> {
    fs::read_dir(root)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .filter(|path| path.file_name().is_some_and(|name| name != "helpers.rs"))
        .map(|path| {
            path.strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

fn collect_unit_harness_paths(path: &Path) -> BTreeMap<String, usize> {
    collect_path_attribute_targets(&fs::read_to_string(path).unwrap())
        .into_iter()
        .filter_map(|target| target.strip_prefix(EXTERNAL_PREFIX).map(str::to_string))
        .fold(BTreeMap::new(), increment_count)
}

fn collect_internal_harness_paths(src_roots: &[PathBuf]) -> BTreeMap<String, usize> {
    src_roots
        .iter()
        .flat_map(|root| collect_rs_files(root))
        .flat_map(|path| collect_path_attribute_targets(&fs::read_to_string(path).unwrap()))
        .filter_map(|target| {
            target
                .split_once(INTERNAL_PREFIX)
                .map(|(_, path)| path.to_string())
        })
        .fold(BTreeMap::new(), increment_count)
}

fn collect_path_attribute_targets(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|line| line.trim().strip_prefix("#[path = \""))
        .filter_map(|line| line.strip_suffix("\"]"))
        .map(str::to_string)
        .collect()
}

fn collect_rs_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_rs_files_into(root, &mut files);
    files
}

fn collect_rs_files_into(root: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_rs_files_into(&path, files);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
}

fn increment_count(mut counts: BTreeMap<String, usize>, path: String) -> BTreeMap<String, usize> {
    *counts.entry(path).or_default() += 1;
    counts
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
