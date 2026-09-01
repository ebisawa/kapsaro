// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public blocking online-verification API.
//! Re-exports the stable service contract without implementation logic.

pub use crate::service::online::{
    GitHubAccount, GitHubOnlineVerifier, OnlineVerificationStatus, VerifiedGitHubEvidence,
};
