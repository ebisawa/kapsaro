// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Shared recipient resolution and validation helpers.

use crate::feature::context::crypto::CryptoContext;
use crate::feature::verify::recipients::verify_recipient_public_keys_from_source;
use crate::model::common::WrapItem;
use crate::model::public_key::VerifiedRecipientKey;
use crate::support::limits::validate_wrap_count;
use crate::{Error, Result};
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
        return Err(Error::build_config_error(
            "Cannot remove all recipients. At least one recipient must remain.".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn build_new_wrap_items<T, Build>(
    current_recipients: &[String],
    current_wrap_count: usize,
    new_recipients: &[String],
    target_members: &[VerifiedRecipientKey],
    mut build_wrap: Build,
) -> Result<Vec<T>>
where
    Build: FnMut(&VerifiedRecipientKey) -> Result<T>,
{
    let attested_pubkeys =
        resolve_new_snapshot_recipients(target_members, new_recipients, current_recipients)?;
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
        Some(members) => resolve_snapshot_verified_recipients(members, recipient_handles),
        None => verify_recipient_public_keys_from_source(
            key_ctx.pub_key_source.as_ref(),
            recipient_handles,
            debug,
        ),
    }
}

pub(crate) fn replace_recipient_wrap_items<Build>(
    wrap_items: &mut Vec<WrapItem>,
    recipient_handles: &[String],
    target_members: &[VerifiedRecipientKey],
    mut build_wrap: Build,
) -> Result<()>
where
    Build: FnMut(&VerifiedRecipientKey) -> Result<WrapItem>,
{
    let refreshed_members =
        resolve_snapshot_verified_recipients(target_members, recipient_handles)?;

    wrap_items.retain(|wrap| !recipient_handles.contains(&wrap.recipient_handle));
    for member in &refreshed_members {
        wrap_items.push(build_wrap(member)?);
    }

    Ok(())
}

fn resolve_new_snapshot_recipients(
    target_members: &[VerifiedRecipientKey],
    recipient_handles: &[String],
    current_recipients: &[String],
) -> Result<Vec<VerifiedRecipientKey>> {
    let recipients = resolve_snapshot_verified_recipients(target_members, recipient_handles)?;
    Ok(filter_existing_recipients(recipients, current_recipients))
}

fn filter_existing_recipients(
    recipients: Vec<VerifiedRecipientKey>,
    current_recipients: &[String],
) -> Vec<VerifiedRecipientKey> {
    let mut filtered = Vec::new();
    for member in recipients {
        let member_handle = &member.document().protected.subject_handle;
        if check_recipient_exists(current_recipients, member_handle) {
            warn!(
                "[CRYPTO] Warning: {} is already a recipient, skipping",
                member_handle
            );
            continue;
        }
        filtered.push(member);
    }
    filtered
}

pub(crate) fn resolve_snapshot_verified_recipients(
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
                .ok_or_else(|| {
                    Error::build_not_found_error(format!(
                        "Member '{}' was not found in the fixed post-promotion snapshot",
                        member_handle
                    ))
                })
        })
        .collect()
}
