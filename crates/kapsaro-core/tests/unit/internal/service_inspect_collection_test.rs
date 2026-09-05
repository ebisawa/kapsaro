// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Internal tests for how inspect names the artifact it loaded.
//! Fixes the source label a parse failure reports back to the operator.

use super::{build_signature_report, load_inspect_content};
use crate::test_utils::with_temp_cwd;

/// A document detection accepts as file-enc and the schema then rejects.
///
/// The failure has to reach the parser to carry a source name, so the content
/// has to pass detection first.
const DETECTED_BUT_INVALID_FILE_ENC: &str =
    r#"{"protected":{"format":"kapsaro:format:file-enc@1"}}"#;

/// The operator reads the failure in the directory they ran the command from,
/// so the artifact is named the way they typed it rather than by its absolute
/// path.
#[test]
fn test_load_inspect_content_names_the_artifact_relative_to_the_working_directory_error() {
    let temp = tempfile::tempdir().unwrap();

    with_temp_cwd(temp.path(), || {
        let cwd = std::env::current_dir().unwrap();
        let artifact_dir = cwd.join("artifacts");
        std::fs::create_dir(&artifact_dir).unwrap();
        let artifact_path = artifact_dir.join("secret.json");
        std::fs::write(&artifact_path, DETECTED_BUT_INVALID_FILE_ENC).unwrap();

        let content = load_inspect_content(&artifact_path).unwrap();
        let error = build_signature_report(&content).unwrap_err();

        let message = error.to_string();
        assert!(
            message.contains("artifacts/secret.json"),
            "unexpected message: {message}"
        );
        assert!(
            !message.contains(cwd.to_str().unwrap()),
            "unexpected message: {message}"
        );
    });
}
