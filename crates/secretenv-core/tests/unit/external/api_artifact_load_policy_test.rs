// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public artifact facade load policy tests.
//!
//! Covers read limits and source labels without depending on CLI behavior.

use std::path::Path;

use secretenv_core::api::file::FileEncArtifact;
use secretenv_core::api::kv::KvEncArtifact;
use secretenv_core::api::operation::OperationOptions;
use secretenv_core::cli_api::test_support::helpers::limits::{
    MAX_JSON_DOCUMENT_READ_SIZE, MAX_KV_ENC_FILE_SIZE,
};
use secretenv_core::{Error, Result};

#[test]
fn file_artifact_load_rejects_over_file_enc_read_limit() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("oversized.env.enc.json");
    save_repeated_bytes(&path, b'A', MAX_JSON_DOCUMENT_READ_SIZE + 1);

    let error = expect_error(FileEncArtifact::load(&path));
    let message = error.format_user_message();

    assert!(message.contains("file-enc artifact exceeds maximum size limit"));
    assert!(message.contains(&(MAX_JSON_DOCUMENT_READ_SIZE + 1).to_string()));
    assert!(message.contains(&source_label(&path)));
}

#[test]
fn kv_artifact_load_rejects_over_kv_read_limit() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("oversized.env.kvenc");
    save_oversized_kv_header_file(&path);

    let error = expect_error(KvEncArtifact::load(&path));
    let message = error.format_user_message();

    assert!(message.contains("kv-enc artifact exceeds maximum size limit"));
    assert!(message.contains(&(MAX_KV_ENC_FILE_SIZE + 1).to_string()));
    assert!(message.contains(&source_label(&path)));
}

#[test]
fn file_artifact_load_uses_path_as_parse_source_label() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("broken.env.enc.json");
    std::fs::write(
        &path,
        r#"{"protected":{"format":"secretenv:format:file-enc@7"}}"#,
    )
    .expect("write file-enc artifact");

    let artifact = FileEncArtifact::load(&path).expect("load file-enc artifact");
    let error = expect_error(artifact.verify(OperationOptions::default()));
    let message = error.format_user_message();

    assert!(message.contains(&format!("Source: {}", source_label(&path))));
    assert!(!message.contains("Source: file-enc content"));
}

#[test]
fn kv_artifact_load_uses_path_as_parse_source_label() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("broken.env.kvenc");
    std::fs::write(&path, ":SECRETENV_KV 9\n:HEAD e30\n:WRAP e30\n:SIG e30\n")
        .expect("write kv-enc artifact");

    let artifact = KvEncArtifact::load(&path).expect("load kv-enc artifact");
    let error = expect_error(artifact.verify(OperationOptions::default()));
    let message = error.format_user_message();

    assert!(message.contains(&source_label(&path)));
    assert!(message.contains("WRAP token"));
    assert!(!message.contains("kv-enc content"));
}

fn save_repeated_bytes(path: &Path, byte: u8, len: usize) {
    std::fs::write(path, vec![byte; len]).expect("write oversized artifact");
}

fn save_oversized_kv_header_file(path: &Path) {
    let mut content = String::from(":SECRETENV_KV 9\n");
    content.push_str(&"A".repeat(MAX_KV_ENC_FILE_SIZE + 1 - content.len()));
    std::fs::write(path, content).expect("write oversized kv-enc artifact");
}

fn source_label(path: &Path) -> String {
    path.display().to_string()
}

fn expect_error<T>(result: Result<T>) -> Error {
    match result {
        Ok(_) => panic!("expected error"),
        Err(error) => error,
    }
}
