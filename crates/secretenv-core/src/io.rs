// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! External I/O adapters (filesystem, SSH, config, online).

pub(crate) mod config;
pub(crate) mod document_store;
pub(crate) mod github;
pub(crate) mod keystore;
pub(crate) mod process;
pub(crate) mod ssh;
pub(crate) mod trust;
pub(crate) mod verify_online;
pub(crate) mod workspace;
