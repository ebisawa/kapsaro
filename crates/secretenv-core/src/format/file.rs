// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! file-enc format canonicalization helpers.

use crate::format::jcs;
use crate::model::file_enc::FileEncDocumentProtected;
use crate::Result;

pub fn build_file_signature_bytes(protected: &FileEncDocumentProtected) -> Result<Vec<u8>> {
    jcs::normalize(protected)
}
