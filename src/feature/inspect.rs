// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Inspect feature - format metadata display.

pub(crate) mod file;
pub(crate) mod kv;

mod formatter;
pub mod verification;

use crate::format::content::EncContent;
use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct InspectSection {
    pub title: String,
    pub lines: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct InspectOutput {
    pub title: String,
    pub sections: Vec<InspectSection>,
}

pub(crate) fn build_section(title: impl Into<String>, lines: Vec<String>) -> InspectSection {
    InspectSection {
        title: title.into(),
        lines,
    }
}

pub fn build_inspect_view(content: &EncContent) -> Result<InspectOutput> {
    match content {
        EncContent::FileEnc(file_content) => {
            let doc = file_content.parse()?;
            Ok(file::build_file_inspect_output(&doc))
        }
        EncContent::KvEnc(kv_content) => {
            let doc = kv_content.parse()?;
            kv::build_kv_inspect_output(&doc)
        }
    }
}
