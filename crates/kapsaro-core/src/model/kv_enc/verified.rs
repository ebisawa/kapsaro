// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Verified wrapper for kv-enc documents.
//! Provides accessor-based access after signature verification succeeds.

use crate::model::kv_enc::document::KvEncDocument;
use crate::model::verified::VerifiedDocument;

pub type VerifiedKvEncDocument = VerifiedDocument<KvEncDocument>;
