// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! JSON renderers for key commands.

use crate::cli::common::output::json::print_json_output;
use crate::cli::common::output::key::view::{KeyInfoView, KeyListView};
use kapsaro_core::Result;
use serde::Serialize;

#[derive(Serialize)]
struct KeyListOutput {
    keys: Vec<KeyInfoJsonView>,
}

#[derive(Serialize)]
struct KeyInfoJsonView {
    kid: String,
    member_handle: String,
    created_at: String,
    expires_at: String,
    active: bool,
    format: String,
}

pub(crate) fn print_empty_key_list() -> Result<()> {
    print_json_output(&KeyListOutput { keys: Vec::new() })
}

pub(crate) fn print_key_list(result: &KeyListView<'_>) -> Result<()> {
    let keys = result
        .entries
        .iter()
        .flat_map(|entry| entry.keys.iter().map(build_key_info_json_view))
        .collect::<Vec<_>>();
    print_json_output(&KeyListOutput { keys })
}

fn build_key_info_json_view(key: &KeyInfoView<'_>) -> KeyInfoJsonView {
    KeyInfoJsonView {
        kid: key.kid.to_string(),
        member_handle: key.member_handle.to_string(),
        created_at: key.created_at.to_string(),
        expires_at: key.expires_at.to_string(),
        active: key.active,
        format: key.format.to_string(),
    }
}
