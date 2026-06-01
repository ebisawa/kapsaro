// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::model::kv_enc::document::KvEncDocument;
use crate::model::kv_enc::header::KvHeader;
use crate::support::time::generate_current_timestamp;
use crate::Result;

pub(crate) fn build_updated_header(doc: &KvEncDocument) -> Result<KvHeader> {
    Ok(KvHeader {
        sid: doc.head.sid,
        alg: doc.head.alg.clone(),
        created_at: doc.head.created_at.clone(),
        updated_at: generate_current_timestamp()?,
    })
}
