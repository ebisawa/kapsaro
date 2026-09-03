// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! trust resign CLI handler.
//!
//! Moves the local trust store signature to the active key without reset recovery:
//! a store whose signer key is gone cannot be re-signed, so the failure is reported as is.
//!
//! This runs straight to `resign_trust_store_command` with no confirmation prompt,
//! unlike `trust approve` / `trust revoke`: re-signing does not change what the store
//! says, only which key vouches for it, so there is no approval content to review
//! before it is written.

use crate::cli::common::context::CliContext;
use crate::cli::common::key_context::load_trust_command_session;
use crate::cli::common::output::text::trust::print_trust_resign_summary;
use kapsaro_core::api::trust::resign::resign_trust_store_command;
use kapsaro_core::Error;

use super::ResignArgs;

pub(crate) fn run(args: ResignArgs) -> Result<(), Error> {
    let context = CliContext::resolve(&args.common)?;
    let session =
        load_trust_command_session(&context, &args.common, args.member.member_handle.clone())?;
    let result = resign_trust_store_command(&session)?;
    print_trust_resign_summary(
        &result.owner_handle,
        &result.previous_signer_kid,
        &result.signer_kid,
        result.resigned,
    );
    Ok(())
}
