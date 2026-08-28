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
#[serde(untagged)]
enum KeyInfoJsonView {
    Complete(CompleteKeyInfoJsonView),
    Incomplete(IncompleteKeyInfoJsonView),
}

#[derive(Serialize)]
struct CompleteKeyInfoJsonView {
    kid: String,
    member_handle: String,
    /// Omitted rather than emitted as null when the stored key predates the
    /// field, so a consumer reading it always gets a timestamp or nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
    expires_at: String,
    active: bool,
    format: String,
}

#[derive(Serialize)]
struct IncompleteKeyInfoJsonView {
    kid: String,
    member_handle: String,
    created_at: Option<String>,
    expires_at: Option<String>,
    active: bool,
    format: Option<String>,
    status: &'static str,
    missing_document: &'static str,
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
    match key {
        KeyInfoView::Complete {
            kid,
            member_handle,
            created_at,
            expires_at,
            active,
            format,
        } => KeyInfoJsonView::Complete(CompleteKeyInfoJsonView {
            kid: (*kid).to_string(),
            member_handle: (*member_handle).to_string(),
            created_at: created_at.map(str::to_string),
            expires_at: (*expires_at).to_string(),
            active: *active,
            format: (*format).to_string(),
        }),
        KeyInfoView::Incomplete {
            kid,
            member_handle,
            active,
            missing_document,
        } => KeyInfoJsonView::Incomplete(IncompleteKeyInfoJsonView {
            kid: (*kid).to_string(),
            member_handle: (*member_handle).to_string(),
            created_at: None,
            expires_at: None,
            active: *active,
            format: None,
            status: "incomplete",
            missing_document,
        }),
    }
}
