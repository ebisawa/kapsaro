// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Trust store readback for service-layer tests.
//! Opens the local state directory a test named and verifies the stored document.

use crate::feature::trust::store_mutation::TrustStoreState;
use crate::model::identity::MemberHandle;
use crate::service::trust::store::load_optional_trust_store;
use crate::service_test_utils::TestCommandOptions;
use crate::support::fs::anchor::AnchoredDir;
use crate::support::fs::relative::{open_optional_child_dir, DirectoryScope};
use crate::Result;

/// Read back the trust store a command wrote under one local state directory.
pub(crate) fn load_test_trust_store(
    options: &TestCommandOptions,
    owner_handle: &str,
) -> Result<Option<TrustStoreState>> {
    let base = AnchoredDir::open(
        options.resolve_base_dir()?,
        DirectoryScope::LocalState,
        "test local state root",
    )?;
    let trust_dir = open_optional_child_dir(&base, "trust")?;
    let owner = MemberHandle::try_from(owner_handle)?;
    load_optional_trust_store(&base, trust_dir.as_ref(), &owner, None)
}
