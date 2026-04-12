// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

use crate::model::kv_enc::header::{KvHeader, KvWrap};
use crate::model::kv_enc::line::KvEncLine;
use crate::model::signature::ArtifactSignature;

pub type KvFileSignature = ArtifactSignature;

#[derive(Debug, Clone)]
pub struct KvEncDocument {
    pub original_content: String,
    pub lines: Vec<KvEncLine>,
    pub head: KvHeader,
    pub wrap: KvWrap,
    pub signature_token: String,
}

impl KvEncDocument {
    pub fn new(
        original_content: String,
        lines: Vec<KvEncLine>,
        head: KvHeader,
        wrap: KvWrap,
        signature_token: String,
    ) -> Self {
        Self {
            original_content,
            lines,
            head,
            wrap,
            signature_token,
        }
    }

    pub fn content(&self) -> &str {
        &self.original_content
    }

    pub fn lines(&self) -> &[KvEncLine] {
        &self.lines
    }

    pub fn head(&self) -> &KvHeader {
        &self.head
    }

    pub fn wrap(&self) -> &KvWrap {
        &self.wrap
    }

    pub fn signature_token(&self) -> &str {
        &self.signature_token
    }
}
