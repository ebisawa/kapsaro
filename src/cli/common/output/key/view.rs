// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! View builders for key command output.

use kapsaro_core::cli_api::app::key::types::{KeyInfo, KeyListResult};

pub(crate) enum KeyInfoView<'a> {
    Complete {
        kid: &'a str,
        member_handle: &'a str,
        created_at: Option<&'a str>,
        expires_at: &'a str,
        active: bool,
        format: &'a str,
    },
    Incomplete {
        kid: &'a str,
        member_handle: &'a str,
        active: bool,
        missing_document: &'static str,
    },
}

pub(crate) struct KeyMemberView<'a> {
    pub(crate) member_handle: &'a str,
    pub(crate) keys: Vec<KeyInfoView<'a>>,
}

pub(crate) struct KeyListView<'a> {
    pub(crate) entries: Vec<KeyMemberView<'a>>,
    pub(crate) total_keys: usize,
}

pub(super) fn build_key_list_view(result: &KeyListResult) -> KeyListView<'_> {
    KeyListView {
        entries: result
            .entries
            .iter()
            .map(|(member_handle, keys)| KeyMemberView {
                member_handle,
                keys: keys
                    .iter()
                    .map(|key| match key {
                        KeyInfo::Complete {
                            kid,
                            member_handle,
                            created_at,
                            expires_at,
                            active,
                            format,
                        } => KeyInfoView::Complete {
                            kid,
                            member_handle,
                            created_at: created_at.as_deref(),
                            expires_at,
                            active: *active,
                            format,
                        },
                        KeyInfo::Incomplete {
                            kid,
                            member_handle,
                            active,
                            missing_document,
                        } => KeyInfoView::Incomplete {
                            kid,
                            member_handle,
                            active: *active,
                            missing_document: missing_document.as_str(),
                        },
                    })
                    .collect(),
            })
            .collect(),
        total_keys: result.total_keys,
    }
}
