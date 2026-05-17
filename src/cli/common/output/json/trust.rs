// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! JSON renderers for trust commands.

use crate::cli::common::output::json::print_json_output;
use crate::cli::common::output::trust::{RecipientSetListItemView, TrustListItemView};
use secretenv_core::Result;
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

#[derive(Serialize)]
struct RecipientSetJsonItem<'a> {
    sid: &'a str,
    recipient_kids: &'a [String],
    recipient_set_hash: &'a str,
    approved_at: &'a str,
    approved_via: &'a str,
}

#[derive(Serialize)]
struct RecipientSetListOutput<'a> {
    recipient_sets: Vec<RecipientSetJsonItem<'a>>,
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

pub(crate) fn print_recipient_set_list(items: &[RecipientSetListItemView<'_>]) -> Result<()> {
    print_json_output(&RecipientSetListOutput {
        recipient_sets: items
            .iter()
            .map(|item| RecipientSetJsonItem {
                sid: item.sid,
                recipient_kids: item.recipient_kids,
                recipient_set_hash: item.recipient_set_hash,
                approved_at: item.approved_at,
                approved_via: item.approved_via,
            })
            .collect(),
    })
}
