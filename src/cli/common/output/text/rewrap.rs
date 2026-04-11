// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Text renderers for rewrap commands.

use crate::cli::common::output::rewrap::RewrapBatchView;

pub(crate) fn print_rewrap_batch_outcome(outcome: &RewrapBatchView) {
    for file in &outcome.processed_files {
        eprintln!("Rewrapped: {}", file);
    }
    for file in &outcome.failed_files {
        eprintln!("Error processing {}: {}", file.path, file.error);
    }
    eprintln!(
        "\nRewraped {} file(s) successfully, {} error(s)",
        outcome.processed_files.len(),
        outcome.failed_files.len()
    );
}
