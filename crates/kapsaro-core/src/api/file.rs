// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Public file-enc artifact API.
//! Re-exports the stable service contract without implementation logic.

pub use crate::service::file::{
    FileEncArtifact, FileReadOperation, TrustedFileEncArtifact, VerifiedFileEncArtifact,
};
