// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Safe filesystem operations shared across local state and workspace storage.
//! Collects fd-relative I/O, permission checks, locking, snapshots, and atomic publication.

pub(crate) mod anchor;
pub mod atomic;
pub mod lock;
pub(crate) mod permission;
pub(crate) mod policy;
pub(crate) mod read;
pub(crate) mod relative;
pub(crate) mod snapshot;
#[cfg(test)]
pub(crate) mod test_umask;

pub(crate) use permission::ensure_dir;
pub use read::{load_bytes, load_text_with_limit};

#[cfg(test)]
#[path = "../../tests/unit/internal/support_fs_test.rs"]
mod support_fs_test;
