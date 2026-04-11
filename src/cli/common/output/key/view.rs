// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! View builders for key command output.

use crate::app::key::types::KeyListResult;

pub(crate) struct KeyInfoView<'a> {
    pub(crate) kid: &'a str,
    pub(crate) member_id: &'a str,
    pub(crate) created_at: &'a str,
    pub(crate) expires_at: &'a str,
    pub(crate) active: bool,
    pub(crate) format: &'a str,
}

pub(crate) struct KeyMemberView<'a> {
    pub(crate) member_id: &'a str,
    pub(crate) keys: Vec<KeyInfoView<'a>>,
}

pub(crate) struct KeyListView<'a> {
    pub(crate) entries: Vec<KeyMemberView<'a>>,
    pub(crate) total_keys: usize,
}

pub(crate) fn build_key_list_view(result: &KeyListResult) -> KeyListView<'_> {
    KeyListView {
        entries: result
            .entries
            .iter()
            .map(|(member_id, keys)| KeyMemberView {
                member_id,
                keys: keys
                    .iter()
                    .map(|key| KeyInfoView {
                        kid: &key.kid,
                        member_id: &key.member_id,
                        created_at: &key.created_at,
                        expires_at: &key.expires_at,
                        active: key.active,
                        format: &key.format,
                    })
                    .collect(),
            })
            .collect(),
        total_keys: result.total_keys,
    }
}
