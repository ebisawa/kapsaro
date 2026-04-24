// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared recipient resolution and validation helpers.

use crate::feature::context::crypto::CryptoContext;
use crate::feature::verify::recipients::verify_recipient_public_keys_from_source;
use crate::model::public_key::VerifiedRecipientKey;
use crate::support::limits::validate_wrap_count;
use crate::{Error, Result};
use std::path::Path;
use tracing::warn;

pub(crate) fn check_recipient_exists(current_recipients: &[String], rid: &str) -> bool {
    current_recipients.iter().any(|recipient| recipient == rid)
}

pub(crate) fn validate_not_empty_recipients(recipients: &[String]) -> Result<()> {
    if recipients.is_empty() {
        return Err(Error::Config {
            message: "Cannot remove all recipients. At least one recipient must remain."
                .to_string(),
        });
    }
    Ok(())
}

pub(crate) fn print_recipient_not_found_warning(rid: &str) {
    warn!("[CRYPTO] Warning: {} is not a recipient, skipping", rid);
}

pub(crate) fn build_new_wrap_items<T, Build>(
    current_recipients: &[String],
    current_wrap_count: usize,
    new_recipients: &[String],
    key_ctx: &CryptoContext,
    target_members: Option<&[VerifiedRecipientKey]>,
    debug: bool,
    mut build_wrap: Build,
) -> Result<Vec<T>>
where
    Build: FnMut(&VerifiedRecipientKey) -> Result<T>,
{
    let attested_pubkeys = resolve_new_verified_recipients(
        target_members,
        key_ctx,
        new_recipients,
        current_recipients,
        debug,
    )?;
    validate_wrap_count(
        current_wrap_count + attested_pubkeys.len(),
        "Updated wrap set",
    )?;
    attested_pubkeys.iter().map(&mut build_wrap).collect()
}

pub(crate) fn resolve_verified_recipients(
    target_members: Option<&[VerifiedRecipientKey]>,
    key_ctx: &CryptoContext,
    recipient_ids: &[String],
    debug: bool,
) -> Result<Vec<VerifiedRecipientKey>> {
    match target_members {
        Some(members) => load_snapshot_verified_recipients(members, recipient_ids),
        None => verify_recipient_public_keys_from_source(
            key_ctx.pub_key_source.as_ref(),
            recipient_ids,
            debug,
        ),
    }
}

pub(crate) fn collect_target_recipient_ids(
    workspace_root: Option<&Path>,
    target_members: Option<&[VerifiedRecipientKey]>,
) -> Result<Vec<String>> {
    match target_members {
        Some(members) => {
            let mut recipients = members
                .iter()
                .map(|member| member.document().protected.member_id.clone())
                .collect::<Vec<_>>();
            recipients.sort();
            Ok(recipients)
        }
        None => {
            let workspace_root = workspace_root.ok_or_else(|| Error::Config {
                message: "rewrap requires a workspace".to_string(),
            })?;
            crate::io::workspace::members::list_active_member_ids(workspace_root)
        }
    }
}

fn resolve_new_verified_recipients(
    target_members: Option<&[VerifiedRecipientKey]>,
    key_ctx: &CryptoContext,
    recipient_ids: &[String],
    current_recipients: &[String],
    debug: bool,
) -> Result<Vec<VerifiedRecipientKey>> {
    let recipients = resolve_verified_recipients(target_members, key_ctx, recipient_ids, debug)?;
    Ok(filter_existing_recipients(recipients, current_recipients))
}

fn print_recipient_already_exists_warning(rid: &str) {
    warn!("[CRYPTO] Warning: {} is already a recipient, skipping", rid);
}

fn filter_existing_recipients(
    recipients: Vec<VerifiedRecipientKey>,
    current_recipients: &[String],
) -> Vec<VerifiedRecipientKey> {
    let mut filtered = Vec::new();
    for member in recipients {
        let member_id = &member.document().protected.member_id;
        if check_recipient_exists(current_recipients, member_id) {
            print_recipient_already_exists_warning(member_id);
            continue;
        }
        filtered.push(member);
    }
    filtered
}

fn load_snapshot_verified_recipients(
    target_members: &[VerifiedRecipientKey],
    member_ids: &[String],
) -> Result<Vec<VerifiedRecipientKey>> {
    member_ids
        .iter()
        .map(|member_id| {
            target_members
                .iter()
                .find(|member| member.document().protected.member_id == *member_id)
                .cloned()
                .ok_or_else(|| Error::NotFound {
                    message: format!(
                        "Member '{}' was not found in the fixed post-promotion snapshot",
                        member_id
                    ),
                })
        })
        .collect()
}
