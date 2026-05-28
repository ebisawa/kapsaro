// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use super::build_rewrap_batch_result_output;
use crate::cli::common::output::rewrap::{RewrapBatchView, RewrapFailureView};

#[test]
fn test_build_rewrap_batch_result_output_success() {
    let view = RewrapBatchView {
        processed_files: vec!["secrets/app.env.encrypted".to_string()],
        failed_files: Vec::new(),
    };

    let output = build_rewrap_batch_result_output(&view);

    assert!(output.success);
    assert_eq!(
        output.summary.processed_files,
        vec!["secrets/app.env.encrypted".to_string()]
    );
    assert!(output.summary.failed_files.is_empty());
}

#[test]
fn test_build_rewrap_batch_result_output_failure() {
    let view = RewrapBatchView {
        processed_files: vec!["secrets/ok.env.encrypted".to_string()],
        failed_files: vec![RewrapFailureView {
            path: "secrets/bad.env.encrypted".to_string(),
            error: "signature verification failed".to_string(),
        }],
    };

    let output = build_rewrap_batch_result_output(&view);

    assert!(!output.success);
    assert_eq!(
        output.summary.processed_files,
        vec!["secrets/ok.env.encrypted".to_string()]
    );
    assert_eq!(
        output.summary.failed_files[0].path,
        "secrets/bad.env.encrypted"
    );
    assert_eq!(
        output.summary.failed_files[0].error,
        "signature verification failed"
    );
}
