// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! External I/O adapters (filesystem, SSH, config, online).

pub mod config;
pub(crate) mod document_store;
pub mod github;
pub mod keystore;
pub mod process;
pub mod ssh;
pub mod trust;
pub mod verify_online;
pub mod workspace;
