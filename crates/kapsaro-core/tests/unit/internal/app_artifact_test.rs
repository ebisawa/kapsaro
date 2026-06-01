// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use std::fs;

use tempfile::tempdir;

use super::{is_encrypted_artifact_file, list_workspace_encrypted_artifacts};

#[test]
fn list_workspace_encrypted_artifacts_returns_sorted_supported_files() {
    let temp_dir = tempdir().unwrap();
    let secrets = temp_dir.path().join("secrets");
    fs::create_dir(&secrets).unwrap();
    fs::write(secrets.join("z.json"), "{}").unwrap();
    fs::write(secrets.join("a.env.encrypted"), "x").unwrap();
    fs::write(secrets.join("m.env.kvenc"), "x").unwrap();
    fs::write(secrets.join("plain.env"), "x").unwrap();
    fs::create_dir(secrets.join("nested.json")).unwrap();

    let paths = list_workspace_encrypted_artifacts(temp_dir.path()).unwrap();
    let names = paths
        .iter()
        .map(|path| path.file_name().unwrap().to_str().unwrap().to_string())
        .collect::<Vec<_>>();

    assert_eq!(names, ["a.env.encrypted", "m.env.kvenc", "z.json"]);
}

#[test]
fn is_encrypted_artifact_file_rejects_directories_and_unknown_extensions() {
    let temp_dir = tempdir().unwrap();
    let json_dir = temp_dir.path().join("dir.json");
    let text_file = temp_dir.path().join("plain.txt");
    fs::create_dir(&json_dir).unwrap();
    fs::write(&text_file, "x").unwrap();

    assert!(!is_encrypted_artifact_file(&json_dir));
    assert!(!is_encrypted_artifact_file(&text_file));
}
