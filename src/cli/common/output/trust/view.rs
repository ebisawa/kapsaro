// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! View builders for trust command output.

pub(crate) struct TrustListItemView<'a> {
    pub(crate) kid: &'a str,
    pub(crate) member_handle: &'a str,
    pub(crate) approved_at: &'a str,
    pub(crate) approved_via: &'a str,
}

pub(crate) struct RecipientSetListItemView<'a> {
    pub(crate) sid: &'a str,
    pub(crate) recipient_kids: &'a [String],
    pub(crate) recipient_set_hash: &'a str,
    pub(crate) approved_at: &'a str,
    pub(crate) approved_via: &'a str,
}

pub(crate) fn build_trust_list_views<'a>(
    items: &'a [secretenv_core::cli_api::app::trust::list::TrustListItem],
) -> Vec<TrustListItemView<'a>> {
    items
        .iter()
        .map(|item| TrustListItemView {
            kid: &item.kid,
            member_handle: &item.member_handle,
            approved_at: &item.approved_at,
            approved_via: &item.approved_via,
        })
        .collect()
}

pub(crate) fn build_recipient_set_list_views<'a>(
    items: &'a [secretenv_core::cli_api::app::trust::list::RecipientSetListItem],
) -> Vec<RecipientSetListItemView<'a>> {
    items
        .iter()
        .map(|item| RecipientSetListItemView {
            sid: &item.sid,
            recipient_kids: &item.recipient_kids,
            recipient_set_hash: &item.recipient_set_hash,
            approved_at: &item.approved_at,
            approved_via: &item.approved_via,
        })
        .collect()
}
