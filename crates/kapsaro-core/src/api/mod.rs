// Copyright 2026 Satoshi Ebisawa
// SPDX-License-Identifier: Apache-2.0

//! Stable facade APIs for external applications.
//! Each module explicitly re-exports an allow-list from the internal service layer.

pub mod config;
pub mod diagnostics;
pub mod doctor;
pub mod file;
pub mod inspect;
pub mod key;
pub mod kv;
pub mod member;
pub mod online;
pub mod operation;
pub mod registration;
pub mod rewrap;
pub mod secret;
pub mod ssh;
pub mod trust;
pub mod workspace;
