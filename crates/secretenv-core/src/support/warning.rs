// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Warning collection helpers.
//! Keeps ordered warning lists deduplicated without changing first-seen order.

pub(crate) fn push_unique_warning(warnings: &mut Vec<String>, warning: String) {
    if !warnings.contains(&warning) {
        warnings.push(warning);
    }
}
