// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! JSON renderers for trust commands.

use crate::cli::common::output::json::print_json_output;
use crate::cli::common::output::trust::TrustListItemView;
use crate::Result;
use serde::Serialize;

#[derive(Serialize)]
struct KnownKeyJsonItem<'a> {
    kid: &'a str,
    subject_handle: &'a str,
    approved_at: &'a str,
    approved_via: &'a str,
}

#[derive(Serialize)]
struct KnownKeyListOutput<'a> {
    known_keys: Vec<KnownKeyJsonItem<'a>>,
}

pub(crate) fn print_known_key_list(items: &[TrustListItemView<'_>]) -> Result<()> {
    print_json_output(&KnownKeyListOutput {
        known_keys: items
            .iter()
            .map(|item| KnownKeyJsonItem {
                kid: item.kid,
                subject_handle: item.member_handle,
                approved_at: item.approved_at,
                approved_via: item.approved_via,
            })
            .collect(),
    })
}
