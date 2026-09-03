// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Reusable standard operations shared by the public API and first-party CLI.
//! Accepts resolved inputs and capabilities without owning CLI orchestration.

pub(crate) mod artifact;
pub(crate) mod artifact_text;
pub(crate) mod config;
pub(crate) mod diagnostics;
pub(crate) mod doctor;
pub(crate) mod errors;
pub(crate) mod file;
pub(crate) mod inspect;
pub(crate) mod key;
pub(crate) mod keystore;
pub(crate) mod kv;
pub(crate) mod member;
pub(crate) mod online;
pub(crate) mod operation;
pub(crate) mod read;
pub(crate) mod registration;
pub(crate) mod rewrap;
pub(crate) mod secret;
pub(crate) mod ssh;
pub(crate) mod trust;
pub(crate) mod workspace;
