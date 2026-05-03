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

pub(crate) fn check_recipient_exists(
    current_recipients: &[String],
    recipient_handle: &str,
) -> bool {
    current_recipients
        .iter()
        .any(|recipient| recipient == recipient_handle)
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

pub(crate) fn print_recipient_not_found_warning(recipient_handle: &str) {
    warn!(
        "[CRYPTO] Warning: {} is not a recipient, skipping",
        recipient_handle
    );
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
    recipient_handles: &[String],
    debug: bool,
) -> Result<Vec<VerifiedRecipientKey>> {
    match target_members {
        Some(members) => load_snapshot_verified_recipients(members, recipient_handles),
        None => verify_recipient_public_keys_from_source(
            key_ctx.pub_key_source.as_ref(),
            recipient_handles,
            debug,
        ),
    }
}

pub(crate) fn collect_target_recipient_handles(
    workspace_root: Option<&Path>,
    target_members: Option<&[VerifiedRecipientKey]>,
) -> Result<Vec<String>> {
    match target_members {
        Some(members) => {
            let mut recipients = members
                .iter()
                .map(|member| member.document().protected.subject_handle.clone())
                .collect::<Vec<_>>();
            recipients.sort();
            Ok(recipients)
        }
        None => {
            let workspace_root = workspace_root.ok_or_else(|| Error::Config {
                message: "rewrap requires a workspace".to_string(),
            })?;
            crate::io::workspace::members::list_active_member_handles(workspace_root)
        }
    }
}

fn resolve_new_verified_recipients(
    target_members: Option<&[VerifiedRecipientKey]>,
    key_ctx: &CryptoContext,
    recipient_handles: &[String],
    current_recipients: &[String],
    debug: bool,
) -> Result<Vec<VerifiedRecipientKey>> {
    let recipients =
        resolve_verified_recipients(target_members, key_ctx, recipient_handles, debug)?;
    Ok(filter_existing_recipients(recipients, current_recipients))
}

fn print_recipient_already_exists_warning(recipient_handle: &str) {
    warn!(
        "[CRYPTO] Warning: {} is already a recipient, skipping",
        recipient_handle
    );
}

fn filter_existing_recipients(
    recipients: Vec<VerifiedRecipientKey>,
    current_recipients: &[String],
) -> Vec<VerifiedRecipientKey> {
    let mut filtered = Vec::new();
    for member in recipients {
        let member_handle = &member.document().protected.subject_handle;
        if check_recipient_exists(current_recipients, member_handle) {
            print_recipient_already_exists_warning(member_handle);
            continue;
        }
        filtered.push(member);
    }
    filtered
}

fn load_snapshot_verified_recipients(
    target_members: &[VerifiedRecipientKey],
    member_handles: &[String],
) -> Result<Vec<VerifiedRecipientKey>> {
    member_handles
        .iter()
        .map(|member_handle| {
            target_members
                .iter()
                .find(|member| member.document().protected.subject_handle == *member_handle)
                .cloned()
                .ok_or_else(|| Error::NotFound {
                    message: format!(
                        "Member '{}' was not found in the fixed post-promotion snapshot",
                        member_handle
                    ),
                })
        })
        .collect()
}
