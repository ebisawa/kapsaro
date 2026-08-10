// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public artifact facade load policy tests.
//!
//! Covers read limits, UTF-8 failure metadata, and source labels without CLI behavior.

use std::error::Error as StdError;
use std::io::Cursor;
use std::path::Path;
use std::str::Utf8Error;

use kapsaro_core::api::file::FileEncArtifact;
use kapsaro_core::api::kv::KvEncArtifact;
use kapsaro_core::api::operation::OperationOptions;
use kapsaro_core::cli_api::presentation::limits::{
    MAX_JSON_DOCUMENT_READ_SIZE, MAX_KV_ENC_FILE_SIZE,
};
use kapsaro_core::{Error, ErrorKind, Result};

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
fn file_artifact_parse_rejects_over_file_enc_read_limit() {
    let content = "A".repeat(MAX_JSON_DOCUMENT_READ_SIZE + 1);

    let error = expect_error(FileEncArtifact::parse(content));
    let message = error.format_user_message();

    assert!(message.contains("file-enc artifact exceeds maximum size limit"));
    assert!(message.contains(&(MAX_JSON_DOCUMENT_READ_SIZE + 1).to_string()));
}

#[test]
fn kv_artifact_reader_rejects_over_kv_read_limit_with_source_label() {
    let content = vec![b'A'; MAX_KV_ENC_FILE_SIZE + 1];

    let error = expect_error(KvEncArtifact::load_reader(
        Cursor::new(content),
        "stdin kv artifact",
    ));
    let message = error.format_user_message();

    assert!(message.contains("kv-enc artifact exceeds maximum size limit"));
    assert!(message.contains(&(MAX_KV_ENC_FILE_SIZE + 1).to_string()));
    assert!(message.contains("stdin kv artifact"));
}

#[test]
fn test_file_artifact_reader_invalid_utf8_metadata_error() {
    let input = b"FILE_SECRET=must-not-appear\n\xff".to_vec();

    assert_invalid_utf8_metadata_error(
        FileEncArtifact::load_reader(Cursor::new(input.clone()), "file reader fixture"),
        &input,
        "file reader fixture",
    );
}

#[test]
fn test_kv_artifact_reader_invalid_utf8_metadata_error() {
    let input = b"KV_SECRET=must-not-appear\n\xff".to_vec();

    assert_invalid_utf8_metadata_error(
        KvEncArtifact::load_reader(Cursor::new(input.clone()), "kv reader fixture"),
        &input,
        "kv reader fixture",
    );
}

#[test]
fn file_artifact_load_uses_path_as_parse_source_label() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("broken.env.enc.json");
    std::fs::write(
        &path,
        r#"{"protected":{"format":"kapsaro:format:file-enc@1"}}"#,
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
    std::fs::write(&path, ":KAPSARO_KV 1\n:HEAD e30\n:WRAP e30\n:SIG e30\n")
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
    let mut content = String::from(":KAPSARO_KV 1\n");
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

fn assert_invalid_utf8_metadata_error<T>(result: Result<T>, input: &[u8], source_name: &str) {
    let error = expect_error(result);

    assert_eq!(error.kind(), ErrorKind::Parse);
    assert!(error.format_user_message().contains(source_name));

    let source = StdError::source(&error).expect("UTF-8 metadata source");
    let utf8_error = source
        .downcast_ref::<Utf8Error>()
        .expect("source must retain only UTF-8 metadata");
    assert_eq!(utf8_error.valid_up_to(), input.len() - 1);
    assert_eq!(utf8_error.error_len(), Some(1));

    let error_debug = format!("{error:?}");
    let input_debug = format!("{input:?}");
    assert!(
        !error_debug.contains(&input_debug),
        "public error Debug output must not retain the input byte buffer"
    );
}
