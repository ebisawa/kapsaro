// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::app::context::options::CommonCommandOptions;
use crate::feature::context::crypto::CryptoContext;
use std::path::Path;
use std::path::PathBuf;

/// Resolved inputs for a batch rewrap command before CLI confirmation.
pub struct RewrapBatchPlan {
    pub workspace_root: PathBuf,
    pub incoming_report: Option<IncomingVerificationReport>,
    pub file_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncomingVerificationCategory {
    Verified,
    Failed,
    NotConfigured,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingGithubAccount {
    pub id: u64,
    pub login: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingVerificationItem {
    pub member_id: String,
    pub category: IncomingVerificationCategory,
    pub message: String,
    pub fingerprint: Option<String>,
    pub github_account: Option<IncomingGithubAccount>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IncomingVerificationReport {
    pub verified: Vec<IncomingVerificationItem>,
    pub failed: Vec<IncomingVerificationItem>,
    pub not_configured: Vec<IncomingVerificationItem>,
}

/// Application-layer request for executing a rewrap batch.
#[derive(Clone)]
pub struct RewrapBatchRequest {
    pub options: CommonCommandOptions,
    pub member_id: Option<String>,
    pub rotate_key: bool,
    pub clear_disclosure_history: bool,
    pub accepted_promotions: Vec<String>,
}

/// Application-layer request for rewrapping a single encrypted document.
#[derive(Clone, Copy)]
pub struct SingleRewrapRequest<'a> {
    pub member_id: &'a str,
    pub key_ctx: &'a CryptoContext,
    pub workspace_root: Option<&'a Path>,
    pub rotate_key: bool,
    pub clear_disclosure_history: bool,
    pub debug: bool,
}

/// A successfully rewritten file.
pub struct RewrapFileSuccess {
    pub output_path: PathBuf,
}

/// A file that failed to rewrap.
pub struct RewrapFileFailure {
    pub output_path: PathBuf,
    pub error_message: String,
}

/// Outcome of a batch rewrap execution.
pub struct RewrapBatchOutcome {
    pub processed_files: Vec<RewrapFileSuccess>,
    pub failed_files: Vec<RewrapFileFailure>,
}
